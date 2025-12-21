use bls12_381::{
    hash_to_curve::{
        ExpandMessageState, ExpandMsgXmd, ExpandMsgXof, HashToCurve, InitExpandMessage,
    },
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};
use rand_core::RngCore;
use sha2::Sha256;
use sha3::Shake256;

// (de)serialization stuff

macro_rules! serialize_g1 {
    ($buf:expr, $off:expr, $point:expr) => {
        $buf[$off..$off + 48].copy_from_slice(&$point.to_compressed());
        $off += 48;
    };
}

macro_rules! serialize_scalar {
    ($buf:expr, $off:expr, $scalar:expr) => {
        $buf[$off..$off + 32].copy_from_slice(&$scalar.to_bytes());
        $buf[$off..$off + 32].reverse();
        $off += 32;
    };
}

macro_rules! serialize_u64 {
    ($buf:expr, $off:expr, $number:expr) => {
        $buf[$off..$off + 8].copy_from_slice(&($number as u64).to_be_bytes());
        $off += 8;
    };
}

macro_rules! deserialize_g1 {
    ($buf:expr, $off:expr) => {{
        let point = G1Affine::from_compressed($buf[$off..$off + 48].try_into().unwrap()).unwrap();
        $off += 48;
        point
    }};
}

macro_rules! deserialize_scalar {
    ($buf:expr, $off:expr) => {{
        let mut bytes: [u8; 32] = $buf[$off..$off + 32].try_into().unwrap();
        bytes.reverse();
        let scalar = Scalar::from_bytes(&bytes).unwrap();
        $off += 32;
        scalar
    }};
}

// constants

const EXPAND_LEN: usize = 48;

const OCTET_SCALAR_LENGTH: usize = 32;
const OCTET_POINT_LENGTH: usize = 48;

/// holds all required cipher suite specific values and functions
pub struct CipherSuite {
    pub api_id: &'static [u8],

    pub p1: [u8; 48],

    pub expand_message: fn(msg: &[u8], dst: &[u8], len_in_bytes: Option<usize>) -> Vec<u8>,

    pub hash_to_curve_g1: fn(msg: &[u8], dst: &[u8]) -> G1Affine,

    pub compare_pairing: fn(bilinear_maps: &[(&G1Affine, &G2Prepared)], result: &Gt) -> bool,
}

// cipher suites

pub const BLS12_381_G1_XOF_SHAKE_256: CipherSuite = CipherSuite {
    api_id: b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_",
    p1: [
        0x89, 0x29, 0xdf, 0xbc, 0x7e, 0x66, 0x42, 0xc4, 0xed, 0x9c, 0xba, 0x08, 0x56, 0xe4, 0x93,
        0xf8, 0xb9, 0xd7, 0xd5, 0xfc, 0xb0, 0xc3, 0x1e, 0xf8, 0xfd, 0xcd, 0x34, 0xd5, 0x06, 0x48,
        0xa5, 0x6c, 0x79, 0x5e, 0x10, 0x6e, 0x9e, 0xad, 0xa6, 0xe0, 0xbd, 0xa3, 0x86, 0xb4, 0x14,
        0x15, 0x07, 0x55,
    ],
    expand_message: |msg: &[u8], dst: &[u8], len: Option<usize>| {
        assert!(dst.len() <= 255, "dst too long");
        ExpandMsgXof::<Shake256>::init_expand(msg, dst, len.unwrap_or(EXPAND_LEN)).into_vec()
    },
    hash_to_curve_g1: |msg: &[u8], dst: &[u8]| {
        assert!(dst.len() <= 255, "dst too long");
        <G1Projective as HashToCurve<ExpandMsgXof<Shake256>>>::hash_to_curve(msg, dst).into()
    },
    compare_pairing: |bilinear_maps: &[(&G1Affine, &G2Prepared)], result: &Gt| {
        multi_miller_loop(bilinear_maps).final_exponentiation() == *result
    },
};

pub const BLS12_381_G1_XMD_SHA_256: CipherSuite = CipherSuite {
    api_id: b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
    p1: [
        0xa8, 0xce, 0x25, 0x61, 0x02, 0x84, 0x08, 0x21, 0xa3, 0xe9, 0x4e, 0xa9, 0x02, 0x5e, 0x46,
        0x62, 0xb2, 0x05, 0x76, 0x2f, 0x97, 0x76, 0xb3, 0xa7, 0x66, 0xc8, 0x72, 0xb9, 0x48, 0xf1,
        0xfd, 0x22, 0x5e, 0x7c, 0x59, 0x69, 0x85, 0x88, 0xe7, 0x0d, 0x11, 0x40, 0x6d, 0x16, 0x1b,
        0x4e, 0x28, 0xc9,
    ],
    expand_message: |msg: &[u8], dst: &[u8], len: Option<usize>| {
        assert!(dst.len() <= 255, "dst too long");
        ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len.unwrap_or(EXPAND_LEN)).into_vec()
    },
    hash_to_curve_g1: |msg: &[u8], dst: &[u8]| {
        assert!(dst.len() <= 255, "dst too long");
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, dst).into()
    },
    compare_pairing: |bilinear_maps: &[(&G1Affine, &G2Prepared)], result: &Gt| {
        multi_miller_loop(bilinear_maps).final_exponentiation() == *result
    },
};

// internal types

struct Proof {
    abar: G1Affine,
    bbar: G1Affine,
    d: G1Affine,
    eh: Scalar,
    r1h: Scalar,
    r3h: Scalar,
    mh: Vec<Scalar>,
    c: Scalar,
}

struct InitRes {
    g1: [G1Affine; 5],
    sc: Scalar,
}

// impls

pub fn proof_verify(
    cs: &CipherSuite,
    pk: &[u8],
    proof: &[u8],
    header: Option<&[u8]>,
    ph: Option<&[u8]>,
    disclosed_messages: Option<&[&[u8]]>,
    disclosed_indexes: Option<Vec<usize>>,
) -> bool {
    let disclosed_messages = disclosed_messages.unwrap_or_default();
    let api_id = [cs.api_id, b"H2G_HM2S_"].concat();

    let r = disclosed_messages.len();

    let proof_len_floor = 3 * OCTET_POINT_LENGTH + 4 * OCTET_SCALAR_LENGTH;
    assert!(proof.len() >= proof_len_floor);
    let u = (proof.len() - proof_len_floor) / OCTET_SCALAR_LENGTH;

    let disclosed_message_scalars = messages_to_scalars(cs, disclosed_messages, Some(&api_id));
    let generators = create_generators(cs, u + r + 1, Some(&api_id));

    core_proof_verify(
        cs,
        pk,
        proof,
        &generators,
        header,
        ph,
        &disclosed_message_scalars,
        &disclosed_indexes.unwrap_or_default(),
        Some(&api_id),
    )
}

fn core_proof_verify(
    cs: &CipherSuite,
    pk: &[u8],
    proof: &[u8],
    generators: &[G1Affine],
    header: Option<&[u8]>,
    ph: Option<&[u8]>,
    disclosed_messages: &[Scalar],
    disclosed_indexes: &[usize],
    api_id: Option<&[u8]>,
) -> bool {
    let api_id = api_id.unwrap_or(&[]);
    let ph = ph.unwrap_or(&[]);

    let proof = octets_to_proof(proof);
    let w = G2Affine::from_compressed(pk.try_into().unwrap()).unwrap();

    let init_res = prepare_proof_verify(
        cs,
        pk,
        &proof,
        generators,
        header,
        disclosed_messages,
        &disclosed_indexes,
        Some(api_id),
    );

    let c = proof_challenge_calculate(
        cs,
        disclosed_messages,
        disclosed_indexes,
        Some(api_id),
        ph,
        &init_res,
    );

    if c != proof.c {
        return false;
    }

    (cs.compare_pairing)(
        &[
            (&proof.abar, &G2Prepared::from(w)),
            (&proof.bbar, &G2Prepared::from(-G2Affine::generator())),
        ],
        &Gt::identity(),
    )
}

fn prepare_proof_verify(
    cs: &CipherSuite,
    pk: &[u8],
    proof: &Proof,
    generators: &[G1Affine],
    header: Option<&[u8]>,
    disclosed_messages: &[Scalar],
    disclosed_indexes: &[usize],
    api_id: Option<&[u8]>,
) -> InitRes {
    let u = proof.mh.len();
    let r = disclosed_indexes.len();
    let l = r + u;

    disclosed_indexes.iter().for_each(|&i| {
        assert!(i < l);
    });

    assert!(
        disclosed_messages.len() == r,
        "wrong number of disclosed messages"
    );
    assert!(generators.len() == l + 1, "wrong number of generators");

    let q1 = generators[0];
    let hp = &generators[1..];

    let disclosed_indexes_set = disclosed_indexes
        .iter()
        .collect::<std::collections::HashSet<_>>();
    let undisclosed_indexes: Vec<usize> = (0..l)
        .filter(|i| !disclosed_indexes_set.contains(i))
        .collect();

    let domain = calculate_domain(cs, pk, &q1, hp, header, api_id);
    let t1 = proof.bbar * proof.c + proof.abar * proof.eh + proof.d * proof.r1h;
    let p1: G1Affine = G1Affine::from_compressed(&cs.p1).unwrap();
    let bv: G1Projective = disclosed_indexes
        .iter()
        .zip(disclosed_messages.iter())
        .fold(p1 + q1 * domain, |acc: G1Projective, (&i, &msg)| {
            acc + hp[i] * msg
        });

    let t2: G1Projective = undisclosed_indexes.iter().zip(proof.mh.iter()).fold(
        bv * proof.c + proof.d * proof.r3h,
        |acc: G1Projective, (&j, &m)| acc + hp[j] * m,
    );

    InitRes {
        g1: [proof.abar, proof.bbar, proof.d, t1.into(), t2.into()],
        sc: domain,
    }
}

fn octets_to_proof(proof: &[u8]) -> Proof {
    let mut off = 0;

    let abar = deserialize_g1!(proof, off);
    let bbar = deserialize_g1!(proof, off);
    let d = deserialize_g1!(proof, off);

    let eh = deserialize_scalar!(proof, off);
    let r1h = deserialize_scalar!(proof, off);
    let r3h = deserialize_scalar!(proof, off);

    let remaining = proof.len() - off;
    let num_scalars = remaining / 32;

    let mh = if num_scalars > 1 {
        (0..num_scalars - 1)
            .map(|_| deserialize_scalar!(proof, off))
            .collect()
    } else {
        Vec::new()
    };

    let c = deserialize_scalar!(proof, off);
    assert!(off == proof.len());

    Proof {
        abar,
        bbar,
        d,
        eh,
        r1h,
        r3h,
        mh,
        c,
    }
}

pub fn proof_gen(
    cs: &CipherSuite,
    pk: &[u8],
    signature: &mut [u8],
    header: Option<&[u8]>,
    ph: Option<&[u8]>,
    messages: &[&[u8]],
    disclosed_indexes: Option<Vec<usize>>,
) -> Box<[u8]> {
    let header = header.unwrap_or(&[]);
    let ph = ph.unwrap_or(&[]);
    let disclosed_indexes = disclosed_indexes.unwrap_or_default();
    let api_id = [cs.api_id, b"H2G_HM2S_"].concat();

    let message_scalars = messages_to_scalars(cs, messages, Some(&api_id));
    let generators = create_generators(cs, messages.len() + 1, Some(&api_id));

    let (a, e) = octets_to_signature(signature);

    let l = messages.len();

    for &i in disclosed_indexes.iter() {
        assert!(i < l, "disclosed indexes out of bounds");
    }

    let undisclosed_indexes = (0..l)
        .filter(|i| !disclosed_indexes.contains(i))
        .collect::<Vec<usize>>();

    let r = disclosed_indexes.len();
    let u = l.checked_sub(r).unwrap();

    let random_scalars = calculate_random_scalars(5 + u);

    let init_res = proof_init(
        cs,
        pk,
        (&a, &e),
        Some(header),
        Some(&api_id),
        &generators,
        &message_scalars,
        &random_scalars,
        &undisclosed_indexes,
    );

    let disclosed_message_scalars: Vec<Scalar> = disclosed_indexes
        .iter()
        .map(|&i| message_scalars[i])
        .collect();

    let challenge = proof_challenge_calculate(
        cs,
        &disclosed_message_scalars,
        &disclosed_indexes,
        Some(&api_id),
        ph,
        &init_res,
    );

    // proof finalize
    proof_finalize(
        &random_scalars,
        &message_scalars,
        &undisclosed_indexes,
        &init_res.g1[0],
        &init_res.g1[1],
        &init_res.g1[2],
        &e,
        &challenge,
    )
}

fn proof_finalize(
    random_scalars: &[Scalar],
    message_scalars: &[Scalar],
    undisclosed_indexes: &[usize],
    abar: &G1Affine,
    bbar: &G1Affine,
    d: &G1Affine,
    e: &Scalar,
    challenge: &Scalar,
) -> Box<[u8]> {
    let r1 = &random_scalars[0]; // r1
    let r2 = &random_scalars[1]; // r2
    let et = &random_scalars[2]; // e~
    let r1t = &random_scalars[3]; // r1~
    let r3t = &random_scalars[4]; // r3~
    let mt = &random_scalars[5..]; // m~j1...m~ju

    let r3 = r2.invert().unwrap();
    let eh = et + e * challenge;
    let r1h = r1t - r1 * challenge;
    let r3h = r3t - r3 * challenge;
    let mh: Vec<Scalar> = mt
        .iter()
        .zip(undisclosed_indexes.iter())
        .map(|(&single_mt, &mi)| single_mt + message_scalars[mi] * challenge)
        .collect();

    // size = abar + bbar + d + eh + r1h + r3h + (len * mt) + challenge
    let size = 48 + 48 + 48 + 32 + 32 + 32 + (mh.len() * 32) + 32;
    // pre calculate size to avoid reallocation
    let mut p_octs: Box<[u8]> = vec![0u8; size].into_boxed_slice();
    let mut off = 0;

    serialize_g1!(p_octs, off, abar);
    serialize_g1!(p_octs, off, bbar);
    serialize_g1!(p_octs, off, d);

    serialize_scalar!(p_octs, off, eh);
    serialize_scalar!(p_octs, off, r1h);
    serialize_scalar!(p_octs, off, r3h);

    mh.iter().for_each(|&m| {
        serialize_scalar!(p_octs, off, m);
    });

    serialize_scalar!(p_octs, off, challenge);
    assert!(off == size);

    p_octs
}

/// calculate the challenge as part of the fiat-shamir heuristic to make the proof protocol non
/// interactive. it hashes the context into the challenge. part of the context is the result of the
/// initialization of the context, the disclosed_messages, and their indexes.
fn proof_challenge_calculate(
    cs: &CipherSuite,
    disclosed_messages: &[Scalar],
    disclosed_indexes: &[usize],
    api_id: Option<&[u8]>,
    ph: &[u8],
    ir: &InitRes,
) -> Scalar {
    let api_id = api_id.unwrap_or(&[]);

    // pre calc length of serialized array for only one alloc call
    let mut size = 8; // 8 bytes for r
    let r = disclosed_indexes.len();
    // bytes for every disclosed index
    size += 8 * r;
    // size of scalar times every disclosed message
    size += disclosed_indexes.len() * 32;
    // (abar + bbar + d + t1 + t2) as G1Affine (48B) & (domain) as Scalar (32B)
    size += 48 + 48 + 48 + 48 + 48 + 32;

    // I2OSP(length(ph), 8) + ph
    size += 8 + ph.len();

    let mut c_octs: Box<[u8]> = vec![0u8; size].into_boxed_slice();
    let mut off = 0;

    serialize_u64!(c_octs, off, r);

    disclosed_indexes
        .iter()
        .zip(disclosed_messages.iter())
        .for_each(|(&di, &msg)| {
            serialize_u64!(c_octs, off, di);
            serialize_scalar!(c_octs, off, msg);
        });

    serialize_g1!(c_octs, off, ir.g1[0]);
    serialize_g1!(c_octs, off, ir.g1[1]);
    serialize_g1!(c_octs, off, ir.g1[2]);
    serialize_g1!(c_octs, off, ir.g1[3]);
    serialize_g1!(c_octs, off, ir.g1[4]);
    serialize_scalar!(c_octs, off, ir.sc);

    serialize_u64!(c_octs, off, ph.len());
    c_octs[off..].copy_from_slice(ph);
    assert!(off + ph.len() == size);

    let hash_to_scalar_dst = [api_id, b"H2S_"].concat();
    hash_to_scalar(cs, &c_octs, &hash_to_scalar_dst)
}

fn proof_init(
    cs: &CipherSuite,
    pk: &[u8],
    signature: (&G1Affine, &Scalar),
    header: Option<&[u8]>,
    api_id: Option<&[u8]>,
    generators: &[G1Affine],
    message_scalars: &[Scalar],
    random_scalars: &[Scalar],
    undisclosed_indexes: &[usize],
) -> InitRes {
    let header = header.unwrap_or(&[]);
    let api_id = api_id.unwrap_or(&[]);
    let (a, e) = signature;

    let q_1 = generators[0];
    let h = &generators[1..];

    let domain = calculate_domain(cs, pk, &q_1, h, Some(header), Some(api_id));

    // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let p_1: G1Affine = G1Affine::from_compressed(&cs.p1).unwrap();
    let b: G1Projective = h
        .iter()
        .zip(message_scalars.iter())
        .fold(p_1 + q_1 * domain, |acc: G1Projective, (h, m)| acc + h * m);

    // OPTIONAL could verify signature using pk and header here

    let r1 = &random_scalars[0]; // r1
    let r2 = &random_scalars[1]; // r2
    let et = &random_scalars[2]; // e~
    let r1t = &random_scalars[3]; // r1~
    let r3t = &random_scalars[4]; // r3~
    let mt = &random_scalars[5..]; // m~j1...m~ju

    // D = B * r2
    let d = b * r2;
    // Abar = A * (r1 * r2)
    let abar = a * (r1 * r2);
    // Bbar = D * r1 - Abar * e
    let bbar = d * r1 - abar * e;

    // T1 = Abar * e~ + D * r1~
    let t1 = abar * et + d * r1t;
    // T2 = D * r3~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
    let t2 = undisclosed_indexes
        .iter()
        .zip(mt.iter())
        .fold(d * r3t, |acc: G1Projective, (&j, &m)| acc + h[j] * m);

    InitRes {
        g1: [abar.into(), bbar.into(), d.into(), t1.into(), t2.into()],
        sc: domain,
    }
}

pub fn verify(
    cs: &CipherSuite,
    pk: &[u8],
    signature: &[u8],
    header: Option<&[u8]>,
    messages: &[&[u8]],
) -> bool {
    let header = header.unwrap_or(&[]);
    let api_id = [cs.api_id, b"H2G_HM2S_"].concat();

    let message_scalars = messages_to_scalars(cs, messages, Some(&api_id));
    let generators = create_generators(cs, messages.len() + 1, Some(&api_id));

    let (a, e) = octets_to_signature(signature);
    let w = G2Affine::from_compressed(&pk.try_into().unwrap()).unwrap();

    let l = message_scalars.len();
    assert!(
        l + 1 == generators.len(),
        "generators and messages dont match"
    );

    let q_1 = generators[0];
    let h = &generators[1..];

    let domain = calculate_domain(cs, pk, &q_1, h, Some(header), Some(&api_id));

    // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let p_1: G1Affine = G1Affine::from_compressed(&cs.p1).unwrap();
    let b: G1Projective = h
        .iter()
        .zip(message_scalars.iter())
        .fold(p_1 + q_1 * domain, |acc: G1Projective, (h, m)| acc + h * m);

    // if h(A, W) * h(A * e - B, BP2) != Identity_GT
    (cs.compare_pairing)(
        &[
            (&a, &G2Prepared::from(w)),
            (
                &G1Affine::from(a * e - b),
                &G2Prepared::from(G2Affine::generator()),
            ),
        ],
        &Gt::identity(),
    )
}

pub fn sign(
    cs: &CipherSuite,
    sk: &[u8],
    pk: &[u8],
    header: Option<&[u8]>,
    messages: &[&[u8]],
) -> Vec<u8> {
    let header = header.unwrap_or(&[]);
    let api_id = [cs.api_id, b"H2G_HM2S_"].concat();

    let message_scalars = messages_to_scalars(cs, messages, Some(&api_id));
    let generators = create_generators(cs, messages.len() + 1, Some(&api_id));

    // core sign
    let hash_to_scalar_dst = [api_id.as_slice(), b"H2S_"].concat();
    let l = message_scalars.len();

    assert!(
        l + 1 == generators.len(),
        "generators and messages dont match"
    );
    let q_1 = generators[0];
    let h = &generators[1..];

    let mut sk_off = 0;
    let sk = deserialize_scalar!(sk, sk_off);

    let domain = calculate_domain(cs, pk, &q_1, h, Some(header), Some(&api_id));

    // serialize((SK, msg_1, ..., msg_L, domain))
    let size = 32 + (message_scalars.len() * 32) + 32;
    let mut octs: Box<[u8]> = vec![0u8; size].into_boxed_slice();
    let mut off = 0;

    serialize_scalar!(octs, off, sk);

    message_scalars.iter().for_each(|msg| {
        serialize_scalar!(octs, off, msg);
    });

    serialize_scalar!(octs, off, domain);
    assert!(off == size);

    // e = hash_to_scalar(serialize((SK, msg_1, ..., msg_L, domain)), hash_to_scalar_dst)
    let e = hash_to_scalar(cs, &octs, &hash_to_scalar_dst);

    // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let p_1: G1Affine = G1Affine::from_compressed(&cs.p1).unwrap();
    let b: G1Projective = h
        .iter()
        .zip(message_scalars.iter())
        .fold(p_1 + q_1 * domain, |acc: G1Projective, (h, m)| acc + h * m);

    // A = B * (1 / (SK + e))
    let a: G1Affine = (b * (sk + e).invert().unwrap()).into();

    signature_to_octets(&a, &e)
}

fn calculate_random_scalars(count: usize) -> Vec<Scalar> {
    (0..count)
        .map(|_| {
            let mut bytes = [0u8; 64];
            rand_core::OsRng.try_fill_bytes(&mut bytes[..48]).unwrap();
            Scalar::from_bytes_wide(&bytes)
        })
        .collect()
}

fn octets_to_signature(signature: &[u8]) -> (G1Affine, Scalar) {
    let mut e_enc: [u8; 32] = signature[48..80].try_into().unwrap();
    e_enc.reverse();
    (
        G1Affine::from_compressed(signature[..48].try_into().unwrap()).unwrap(),
        Scalar::from_bytes(&e_enc).unwrap(),
    )
}

fn signature_to_octets(a: &G1Affine, e: &Scalar) -> Vec<u8> {
    // Serialize A (G1 point) in compressed form (48 bytes)
    let a_bytes = a.to_compressed();

    // Serialize e (scalar) as 32 bytes, must reverse because Scalar is little endianess
    let mut bytes = e.to_bytes();
    bytes.reverse();
    assert!(
        bytes.len() <= OCTET_SCALAR_LENGTH,
        "value too large to be serialized"
    );

    let mut e_bytes = [0u8; OCTET_SCALAR_LENGTH];
    let start = OCTET_SCALAR_LENGTH - bytes.len();
    e_bytes[start..].copy_from_slice(&bytes);

    // Concatenate: A || e (48 + 32 = 80 bytes total)
    [&a_bytes[..], &e_bytes[..]].concat()
}

fn calculate_domain(
    cs: &CipherSuite,
    pk: &[u8],
    q_1: &G1Affine,
    h_points: &[G1Affine],
    header: Option<&[u8]>,
    api_id: Option<&[u8]>,
) -> Scalar {
    let api_id = api_id.unwrap_or(&[]);
    let header = header.unwrap_or(&[]);

    let hash_to_scalar_dst = [api_id, b"H2S_"].concat();

    let l = h_points.len();

    // dom_array = (L, Q_1, H_1, ..., H_L)
    // dom_octs = serialize(dom_array) || api_id
    // dom_input = PK || dom_octs || I2OSP(length(header), 8) || header
    let size = pk.len() + 8 + 48 + (h_points.len() * 48) + api_id.len() + 8 + header.len();
    let mut dom_input: Box<[u8]> = vec![0u8; size].into_boxed_slice();
    let mut off = 0;

    dom_input[..pk.len()].copy_from_slice(pk);
    off += pk.len();

    // dom_octs
    serialize_u64!(dom_input, off, l);
    serialize_g1!(dom_input, off, q_1);

    h_points.iter().for_each(|h| {
        serialize_g1!(dom_input, off, h);
    });

    dom_input[off..off + api_id.len()].copy_from_slice(api_id);
    off += api_id.len();

    serialize_u64!(dom_input, off, header.len());

    dom_input[off..].copy_from_slice(header);
    assert!(off + header.len() == size);

    hash_to_scalar(cs, &dom_input, &hash_to_scalar_dst)
}

fn create_generators(cs: &CipherSuite, count: usize, api_id: Option<&[u8]>) -> Vec<G1Affine> {
    let api_id = api_id.unwrap_or(&[]);

    let seed_dst = [api_id, b"SIG_GENERATOR_SEED_"].concat();
    let generator_dst = [api_id, b"SIG_GENERATOR_DST_"].concat();
    let generator_seed = [api_id, b"MESSAGE_GENERATOR_SEED"].concat();

    let mut generators = Vec::with_capacity(count);

    let mut v = (cs.expand_message)(&generator_seed, &seed_dst, Some(EXPAND_LEN));

    for i in 1..=count {
        let i_bytes = (i as u64).to_be_bytes();
        let input = [&v[..], &i_bytes].concat();
        v = (cs.expand_message)(&input, &seed_dst, Some(EXPAND_LEN));

        let generator_i = (cs.hash_to_curve_g1)(&v, &generator_dst);
        generators.push(generator_i);
    }

    generators
}

fn messages_to_scalars(cs: &CipherSuite, messages: &[&[u8]], api_id: Option<&[u8]>) -> Vec<Scalar> {
    // ABORT if length(messages) > 2^64 - 1
    // This is automatically satisfied since Vec can't exceed usize::MAX
    // which is at most 2^64 - 1 on 64-bit systems

    let api_id = api_id.unwrap_or(&[]);

    let map_dst = [api_id, b"MAP_MSG_TO_SCALAR_AS_HASH_"].concat();

    let msg_scalars: Vec<Scalar> = messages
        .iter()
        .map(|msg| hash_to_scalar(cs, msg, &map_dst))
        .collect();

    msg_scalars
}

pub fn sk_to_pk(sk: &Scalar) -> Vec<u8> {
    let w = G2Projective::generator() * sk;

    point_to_octets_e2(&w)
}

fn point_to_octets_e2(point: &G2Projective) -> Vec<u8> {
    let affine: G2Affine = point.into();
    affine.to_compressed().to_vec()
}

pub fn key_gen(
    cs: &CipherSuite,
    key_material: &[u8],
    key_info: &[u8],
    key_dst: Option<&[u8]>,
) -> Scalar {
    assert!(key_material.len() >= 32, "key_material is too short");
    assert!(key_info.len() <= 65535, "key_info is too long");

    let default_dst;
    let key_dst = if let Some(dst) = key_dst {
        dst
    } else {
        default_dst = [cs.api_id, b"KEYGEN_DST_"].concat();
        &default_dst
    };

    let key_info_len = (key_info.len() as u16).to_be_bytes().to_vec();
    let derive_input = [key_material, &key_info_len, key_info].concat();

    hash_to_scalar(cs, &derive_input, key_dst)
}

fn hash_to_scalar(cs: &CipherSuite, msg_octets: &[u8], dst: &[u8]) -> Scalar {
    assert!(dst.len() <= 255, "DST too long");

    let uniform_bytes = (cs.expand_message)(msg_octets, dst, Some(EXPAND_LEN));

    // convert endianess
    let mut wide_bytes = [0u8; 64];
    wide_bytes[16..].copy_from_slice(&uniform_bytes);
    wide_bytes.reverse();

    Scalar::from_bytes_wide(&wide_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;
    use std::path::Path;

    // convert big endian byte arrays into little endian and then scalars
    fn bytes_be_to_scalar(bytes: &[u8; 32]) -> Scalar {
        let mut tmp = [0u8; 64];
        tmp[32..].copy_from_slice(bytes);
        tmp.reverse();
        Scalar::from_bytes_wide(&tmp)
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SignerKeyPair {
        public_key: String,
        secret_key: String,
    }

    #[derive(Deserialize)]
    struct TestResult {
        valid: bool,
        reason: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TestVector {
        case_name: String,
        signer_key_pair: SignerKeyPair,
        header: String,
        messages: Vec<String>,
        signature: String,
        result: TestResult,
    }

    fn run_signature_test<F>(path: &Path, verify_fn: F)
    where
        F: Fn(&[u8], &[u8], &[u8], &[u8], &[&[u8]]) -> bool,
    {
        let json_content = fs::read_to_string(path).expect("failed to read file");

        let vector: TestVector = serde_json::from_str(&json_content).expect("failed to parse json");

        let pk_bytes = hex::decode(&vector.signer_key_pair.public_key).unwrap();
        let sk_bytes = hex::decode(&vector.signer_key_pair.secret_key).unwrap();
        let header_bytes = hex::decode(&vector.header).unwrap();
        let sig_bytes = hex::decode(&vector.signature).unwrap();
        let msg_bytes: Vec<Vec<u8>> = vector
            .messages
            .iter()
            .map(|m| hex::decode(m).expect("invalid hex in messages"))
            .collect();
        let msg_slices: Vec<&[u8]> = msg_bytes.iter().map(|m| m.as_slice()).collect();

        let is_valid = verify_fn(&pk_bytes, &sk_bytes, &header_bytes, &sig_bytes, &msg_slices);

        assert_eq!(
            is_valid,
            vector.result.valid,
            "test case '{}' failed in file {:?} with reason {}",
            vector.case_name,
            path.file_name().unwrap(),
            vector.result.reason.unwrap_or_default()
        );
    }

    fn run_signature_test_vectors_in_dir<F>(dir_path: &str, verify_fn: F)
    where
        F: Fn(&[u8], &[u8], &[u8], &[u8], &[&[u8]]) -> bool + Copy,
    {
        let paths = fs::read_dir(dir_path).expect("could not find directory");

        for entry in paths {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                run_signature_test(&path, verify_fn);
            }
        }
    }

    #[test]
    fn bls12_381_sha_256_signatures() {
        run_signature_test_vectors_in_dir(
            "./test_fixtures/bls12-381-sha-256/signature",
            |pk, sk, header, sig, msgs| {
                let signature = sign(&BLS12_381_G1_XMD_SHA_256, sk, pk, Some(header), msgs);
                if sig != signature {
                    return false;
                }

                verify(
                    &BLS12_381_G1_XMD_SHA_256,
                    pk,
                    &signature,
                    Some(header),
                    msgs,
                )
            },
        );
    }

    #[test]
    fn bls12_381_shake_256_signatures() {
        run_signature_test_vectors_in_dir(
            "./test_fixtures/bls12-381-shake-256/signature",
            |pk, sk, header, sig, msgs| {
                let signature = sign(&BLS12_381_G1_XOF_SHAKE_256, sk, pk, Some(header), msgs);
                if sig != signature {
                    return false;
                }

                verify(
                    &BLS12_381_G1_XOF_SHAKE_256,
                    pk,
                    &signature,
                    Some(header),
                    msgs,
                )
            },
        );
    }

    #[derive(Deserialize)]
    struct RandomScalars {
        r1: String,
        r2: String,
        e_tilde: String,
        r1_tilde: String,
        r3_tilde: String,
        m_tilde_scalars: Vec<String>,
    }

    #[derive(Deserialize)]
    struct ProofTraceRaw {
        random_scalars: RandomScalars,
        A_bar: String,
        B_bar: String,
        D: String,
        T1: String,
        T2: String,
        domain: String,
        challenge: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofTestVector {
        case_name: String,
        signer_public_key: String,
        signature: String,
        header: String,
        presentation_header: String,
        messages: Vec<String>,
        disclosed_indexes: Vec<usize>,
        proof: String,
        result: TestResult,
        trace: ProofTraceRaw,
    }

    struct ProofTrace {
        random_scalars: Vec<Scalar>,
        abar: G1Affine,
        bbar: G1Affine,
        d: G1Affine,
        t1: G1Affine,
        t2: G1Affine,
        domain: Scalar,
        challenge: Scalar,
    }

    fn get_random_scalars(ptv: &ProofTestVector) -> Vec<String> {
        let rs = &ptv.trace.random_scalars;
        let mut scalars = vec![
            rs.r1.clone(),
            rs.r2.clone(),
            rs.e_tilde.clone(),
            rs.r1_tilde.clone(),
            rs.r3_tilde.clone(),
        ];
        scalars.extend(rs.m_tilde_scalars.iter().cloned());
        scalars
    }

    fn run_proof_test<G, V>(path: &Path, proof_gen_fn: G, proof_verify_fn: V)
    where
        // G: (pk, proof, sig, header, ph, msgs, disclosed_msgs, disclosed_idxs, proof_trace) -> bool
        G: Fn(
            &[u8],
            &[u8],
            &mut [u8],
            Option<&[u8]>,
            Option<&[u8]>,
            &[&[u8]],
            Option<Vec<usize>>,
            &ProofTrace,
        ) -> bool,
        // V: (pk, proof, header, ph, disclosed_msgs, disclosed_idxs)
        V: Fn(
            &[u8],
            &[u8],
            Option<&[u8]>,
            Option<&[u8]>,
            Option<&[&[u8]]>,
            Option<Vec<usize>>,
        ) -> bool,
    {
        let json_content = fs::read_to_string(path).unwrap();
        let vector: ProofTestVector = serde_json::from_str(&json_content).unwrap();

        println!("testing {}", vector.case_name);

        let pk_bytes = hex::decode(&vector.signer_public_key).unwrap();
        let mut sig_bytes = hex::decode(&vector.signature).unwrap();
        let expected_proof = hex::decode(&vector.proof).unwrap();
        let header = hex::decode(&vector.header).unwrap();
        let ph = hex::decode(&vector.presentation_header).unwrap();

        let msg_data: Vec<Vec<u8>> = vector
            .messages
            .iter()
            .map(|m| hex::decode(m).unwrap())
            .collect();

        let msg_slices: Vec<&[u8]> = msg_data.iter().map(|m| m.as_slice()).collect();

        // trace stuff
        let mut pt: ProofTrace = ProofTrace {
            random_scalars: Vec::new(),
            abar: G1Affine::from_compressed(
                &hex::decode(&vector.trace.A_bar)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            bbar: G1Affine::from_compressed(
                &hex::decode(&vector.trace.B_bar)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            d: G1Affine::from_compressed(
                &hex::decode(&vector.trace.D).unwrap().try_into().unwrap(),
            )
            .unwrap(),
            t1: G1Affine::from_compressed(
                &hex::decode(&vector.trace.T1).unwrap().try_into().unwrap(),
            )
            .unwrap(),
            t2: G1Affine::from_compressed(
                &hex::decode(&vector.trace.T2).unwrap().try_into().unwrap(),
            )
            .unwrap(),
            domain: bytes_be_to_scalar(
                &hex::decode(&vector.trace.domain)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            challenge: bytes_be_to_scalar(
                &hex::decode(&vector.trace.challenge)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
        };

        let scalar_data: Vec<Vec<u8>> = get_random_scalars(&vector)
            .iter()
            .map(|s| hex::decode(s).expect("invalid scalar hex"))
            .collect();

        for raw_scalar in scalar_data {
            pt.random_scalars
                .push(bytes_be_to_scalar(&raw_scalar.try_into().unwrap()));
        }

        if vector.result.valid {
            assert!(
                proof_gen_fn(
                    &pk_bytes,
                    &expected_proof,
                    &mut sig_bytes,
                    Some(&header),
                    Some(&ph),
                    &msg_slices,
                    Some(vector.disclosed_indexes.clone()),
                    &pt,
                ),
                "failed proof gen in test case: {}",
                vector.case_name
            );
        }

        let disclosed_messages: Vec<&[u8]> = vector
            .disclosed_indexes
            .iter()
            .map(|&i| msg_slices[i])
            .collect();

        assert_eq!(
            proof_verify_fn(
                &pk_bytes,
                &expected_proof,
                Some(&header),
                Some(&ph),
                Some(&disclosed_messages),
                Some(vector.disclosed_indexes)
            ),
            vector.result.valid,
            "failed proof verify in test case {}",
            vector.case_name
        );
    }

    fn run_all_proof_vectors<G, V>(dir: &str, proof_gen_fn: G, proof_verify_fn: V)
    where
        // G: (pk, proof, sig, header, ph, msgs, disclosed_msgs, disclosed_idxs, proof_trace) -> bool
        G: Fn(
                &[u8],
                &[u8],
                &mut [u8],
                Option<&[u8]>,
                Option<&[u8]>,
                &[&[u8]],
                Option<Vec<usize>>,
                &ProofTrace,
            ) -> bool
            + Copy,
        // V: (pk, proof, header, ph, disclosed_msgs, disclosed_idxs)
        V: Fn(
                &[u8],
                &[u8],
                Option<&[u8]>,
                Option<&[u8]>,
                Option<&[&[u8]]>,
                Option<Vec<usize>>,
            ) -> bool
            + Copy,
    {
        let paths = fs::read_dir(dir).unwrap();
        for entry in paths {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                run_proof_test(&path, proof_gen_fn, proof_verify_fn);
            }
        }
    }

    fn test_proof_gen(
        cs: &CipherSuite,
        pk: &[u8],
        expected_proof: &[u8],
        sig: &mut [u8],
        header: Option<&[u8]>,
        ph: Option<&[u8]>,
        msgs: &[&[u8]],
        disclosed_indexes: Option<Vec<usize>>,
        pt: &ProofTrace,
    ) -> bool {
        let api_id = [cs.api_id, b"H2G_HM2S_"].concat();
        let disclosed_indexes = disclosed_indexes.unwrap_or_default();

        let message_scalars = messages_to_scalars(cs, msgs, Some(&api_id));
        let generators = create_generators(cs, msgs.len() + 1, Some(&api_id));

        let (a, e) = octets_to_signature(sig);

        let l = msgs.len();

        for &i in disclosed_indexes.iter() {
            assert!(i < l, "disclosed indexes out of bounds");
        }

        let undisclosed_indexes = (0..l)
            .filter(|i| !disclosed_indexes.contains(i))
            .collect::<Vec<usize>>();

        let init_res = proof_init(
            cs,
            pk,
            (&a, &e),
            header,
            Some(&api_id),
            &generators,
            &message_scalars,
            &pt.random_scalars,
            &undisclosed_indexes,
        );

        assert_eq!(init_res.g1[0], pt.abar);
        assert_eq!(init_res.g1[1], pt.bbar);
        assert_eq!(init_res.g1[2], pt.d);
        assert_eq!(init_res.g1[3], pt.t1);
        assert_eq!(init_res.g1[4], pt.t2);
        assert_eq!(init_res.sc, pt.domain);

        let disclosed_message_scalars: Vec<Scalar> = disclosed_indexes
            .iter()
            .map(|&i| message_scalars[i])
            .collect();

        let challenge = proof_challenge_calculate(
            cs,
            &disclosed_message_scalars,
            &disclosed_indexes,
            Some(&api_id),
            ph.unwrap_or_default(),
            &init_res,
        );

        assert_eq!(challenge, pt.challenge);

        let proof = proof_finalize(
            &pt.random_scalars,
            &message_scalars,
            &undisclosed_indexes,
            &init_res.g1[0],
            &init_res.g1[1],
            &init_res.g1[2],
            &e,
            &challenge,
        );

        assert_eq!(proof.as_ref(), expected_proof);

        true
    }

    #[test]
    fn bls12_381_sha_256_proofs() {
        run_all_proof_vectors(
            "./test_fixtures/bls12-381-sha-256/proof",
            |pk, expected_proof, sig, header, ph, msgs, idxs, pt| {
                let cs = &BLS12_381_G1_XMD_SHA_256;
                test_proof_gen(cs, pk, expected_proof, sig, header, ph, msgs, idxs, pt)
            },
            |pk, proof, header, ph, disclosed_messages, disclosed_indexes| {
                let cs = &BLS12_381_G1_XMD_SHA_256;
                proof_verify(
                    cs,
                    pk,
                    proof,
                    header,
                    ph,
                    disclosed_messages,
                    disclosed_indexes,
                )
            },
        );
    }

    #[test]
    fn bls12_381_shake_256_proofs() {
        run_all_proof_vectors(
            "./test_fixtures/bls12-381-shake-256/proof",
            |pk, expected_proof, sig, header, ph, msgs, idxs, pt| {
                let cs = &BLS12_381_G1_XOF_SHAKE_256;
                test_proof_gen(cs, pk, expected_proof, sig, header, ph, msgs, idxs, pt)
            },
            |pk, proof, header, ph, disclosed_messages, disclosed_indexes| {
                let cs = &BLS12_381_G1_XOF_SHAKE_256;
                proof_verify(
                    cs,
                    pk,
                    proof,
                    header,
                    ph,
                    disclosed_messages,
                    disclosed_indexes,
                )
            },
        );
    }

    pub const M1: &[u8] = &[
        0x98, 0x72, 0xad, 0x08, 0x9e, 0x45, 0x2c, 0x7b, 0x6e, 0x28, 0x3d, 0xfa, 0xc2, 0xa8, 0x0d,
        0x58, 0xe8, 0xd0, 0xff, 0x71, 0xcc, 0x4d, 0x5e, 0x31, 0x0a, 0x1d, 0xeb, 0xdd, 0xa4, 0xa4,
        0x5f, 0x02,
    ];
    pub const M2: &[u8] = &[
        0xc3, 0x44, 0x13, 0x6d, 0x9a, 0xb0, 0x2d, 0xa4, 0xdd, 0x59, 0x08, 0xbb, 0xba, 0x91, 0x3a,
        0xe6, 0xf5, 0x8c, 0x2c, 0xc8, 0x44, 0xb8, 0x02, 0xa6, 0xf8, 0x11, 0xf5, 0xfb, 0x07, 0x5f,
        0x9b, 0x80,
    ];
    pub const M3: &[u8] = &[
        0x73, 0x72, 0xe9, 0xda, 0xa5, 0xed, 0x31, 0xe6, 0xcd, 0x5c, 0x82, 0x5e, 0xac, 0x1b, 0x85,
        0x5e, 0x84, 0x47, 0x6a, 0x1d, 0x94, 0x93, 0x2a, 0xa3, 0x48, 0xe0, 0x7b, 0x73,
    ];
    pub const M4: &[u8] = &[
        0x77, 0xfe, 0x97, 0xeb, 0x97, 0xa1, 0xeb, 0xe2, 0xe8, 0x1e, 0x4e, 0x35, 0x97, 0xa3, 0xee,
        0x74, 0x0a, 0x66, 0xe9, 0xef, 0x24, 0x12, 0x47, 0x2c,
    ];
    pub const M5: &[u8] = &[
        0x49, 0x66, 0x94, 0x77, 0x4c, 0x56, 0x04, 0xab, 0x1b, 0x25, 0x44, 0xea, 0xba, 0xbc, 0xf0,
        0xf5, 0x32, 0x78, 0xff, 0x50,
    ];
    pub const M6: &[u8] = &[
        0x51, 0x5a, 0xe1, 0x53, 0xe2, 0x2a, 0xae, 0x04, 0xad, 0x16, 0xf7, 0x59, 0xe0, 0x72, 0x37,
        0xb4,
    ];
    pub const M7: &[u8] = &[
        0xd1, 0x83, 0xdd, 0xc6, 0xe2, 0x66, 0x5a, 0xa4, 0xe2, 0xf0, 0x88, 0xaf,
    ];
    pub const M8: &[u8] = &[0xac, 0x55, 0xfb, 0x33, 0xa7, 0x59, 0x09, 0xed];
    pub const M9: &[u8] = &[0x96, 0x01, 0x20, 0x96];
    pub const M10: &[u8] = &[];

    #[test]
    fn just_another_test() {
        let cs = BLS12_381_G1_XMD_SHA_256;

        let sc = [
            0x1b, 0x6f, 0x40, 0x6b, 0x17, 0xaa, 0xf9, 0x2d, 0xc7, 0xde, 0xb9, 0x11, 0xc7, 0xca,
            0xe4, 0x97, 0x56, 0xa6, 0x62, 0x3b, 0x5c, 0x38, 0x5b, 0x5a, 0xe6, 0x21, 0x4d, 0x7e,
            0x3d, 0x95, 0x97, 0xf7,
        ];

        let dst = b"BLIND_BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_";

        let gens = create_generators(&cs, 1, Some(dst));

        let scal = bytes_be_to_scalar(&sc);

        println!("Q2: {:x?}", gens[0].to_compressed());
        let res = gens[0] * scal;
        println!("RES: {:x?}", G1Affine::from(res).to_compressed());
    }

    #[test]
    fn bls12_381_sha256_create_generators_1() {
        let cs = BLS12_381_G1_XMD_SHA_256;

        let input_count = 11;
        let api_id = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";

        let generators = create_generators(&cs, input_count, Some(api_id));

        let q1 = [
            0xa9, 0xec, 0x65, 0xb7, 0x0a, 0x7f, 0xbe, 0x40, 0xc8, 0x74, 0xc9, 0xeb, 0x04, 0x1c,
            0x2c, 0xb0, 0xa7, 0xaf, 0x36, 0xcc, 0xec, 0x1b, 0xea, 0x48, 0xfa, 0x2b, 0xa4, 0xc2,
            0xeb, 0x67, 0xef, 0x7f, 0x9e, 0xcb, 0x17, 0xed, 0x27, 0xd3, 0x8d, 0x27, 0xcd, 0xed,
            0xdf, 0xf4, 0x4c, 0x81, 0x37, 0xbe,
        ];

        let expected_generators = [
            [
                0x98, 0xcd, 0x53, 0x13, 0x28, 0x3a, 0xaf, 0x5d, 0xb1, 0xb3, 0xba, 0x86, 0x11, 0xfe,
                0x60, 0x70, 0xd1, 0x9e, 0x60, 0x5d, 0xe4, 0x07, 0x8c, 0x38, 0xdf, 0x36, 0x01, 0x9f,
                0xba, 0xad, 0x0b, 0xd2, 0x8d, 0xd0, 0x90, 0xfd, 0x24, 0xed, 0x27, 0xf7, 0xf4, 0xd2,
                0x2d, 0x5f, 0xf5, 0xde, 0xa7, 0xd4,
            ],
            [
                0xa3, 0x1f, 0xbe, 0x20, 0xc5, 0xc1, 0x35, 0xbc, 0xaa, 0x8d, 0x9f, 0xc4, 0xe4, 0xac,
                0x66, 0x5c, 0xc6, 0xdb, 0x02, 0x26, 0xf3, 0x5e, 0x73, 0x75, 0x07, 0xe8, 0x03, 0x04,
                0x40, 0x93, 0xf3, 0x76, 0x97, 0xa9, 0xd4, 0x52, 0x49, 0x0a, 0x97, 0x0e, 0xea, 0x6f,
                0x9a, 0xd6, 0xc3, 0xdc, 0xaa, 0x3a,
            ],
            [
                0xb4, 0x79, 0x26, 0x34, 0x45, 0xf4, 0xd2, 0x10, 0x89, 0x65, 0xa9, 0x08, 0x6f, 0x9d,
                0x1f, 0xdc, 0x8c, 0xde, 0x77, 0xd1, 0x4a, 0x91, 0xc8, 0x56, 0x76, 0x95, 0x21, 0xad,
                0x33, 0x44, 0x75, 0x4c, 0xc5, 0xce, 0x90, 0xd9, 0xbc, 0x4c, 0x69, 0x6d, 0xff, 0xbc,
                0x9e, 0xf1, 0xd6, 0xad, 0x1b, 0x62,
            ],
            [
                0xac, 0x04, 0x01, 0x76, 0x6d, 0x21, 0x28, 0xd4, 0x79, 0x1d, 0x92, 0x25, 0x57, 0xc7,
                0xb4, 0xd1, 0xae, 0x9a, 0x9b, 0x50, 0x8c, 0xe2, 0x66, 0x57, 0x52, 0x44, 0xa8, 0xd6,
                0xf3, 0x21, 0x10, 0xd7, 0xb0, 0xb7, 0x55, 0x7b, 0x77, 0x60, 0x48, 0x69, 0x63, 0x3b,
                0xb4, 0x9a, 0xfb, 0xe2, 0x00, 0x35,
            ],
            [
                0xb9, 0x5d, 0x28, 0x98, 0x37, 0x0e, 0xbc, 0x54, 0x28, 0x57, 0x74, 0x6a, 0x31, 0x6c,
                0xe3, 0x2f, 0xa5, 0x15, 0x1c, 0x31, 0xf9, 0xb5, 0x79, 0x15, 0xe3, 0x08, 0xee, 0x9d,
                0x1d, 0xe7, 0xdb, 0x69, 0x12, 0x7d, 0x91, 0x9e, 0x98, 0x4e, 0xa0, 0x74, 0x7f, 0x52,
                0x23, 0x82, 0x1b, 0x59, 0x63, 0x35,
            ],
            [
                0x8f, 0x19, 0x35, 0x9a, 0xe6, 0xee, 0x50, 0x81, 0x57, 0x49, 0x2c, 0x06, 0x76, 0x5b,
                0x7d, 0xf0, 0x9e, 0x2e, 0x5a, 0xd5, 0x91, 0x11, 0x57, 0x42, 0xf2, 0xde, 0x9c, 0x08,
                0x57, 0x2b, 0xb2, 0x84, 0x5c, 0xbf, 0x03, 0xfd, 0x7e, 0x23, 0xb7, 0xf0, 0x31, 0xed,
                0x9c, 0x75, 0x64, 0xe5, 0x2f, 0x39,
            ],
            [
                0xab, 0xc9, 0x14, 0xab, 0xe2, 0x92, 0x63, 0x24, 0xb2, 0xc8, 0x48, 0xe8, 0xa4, 0x11,
                0xa2, 0xb6, 0xdf, 0x18, 0xcb, 0xe7, 0x75, 0x8d, 0xb8, 0x64, 0x41, 0x45, 0xfe, 0xfb,
                0x0b, 0xf0, 0xa2, 0xd5, 0x58, 0xa8, 0xc9, 0x94, 0x6b, 0xd3, 0x5e, 0x00, 0xc6, 0x9d,
                0x16, 0x7a, 0xad, 0xf3, 0x04, 0xc1,
            ],
            [
                0x80, 0x75, 0x5b, 0x3e, 0xb0, 0xdd, 0x42, 0x49, 0xcb, 0xef, 0xd2, 0x0f, 0x17, 0x7c,
                0xee, 0x88, 0xe0, 0x76, 0x1c, 0x06, 0x6b, 0x71, 0x79, 0x48, 0x25, 0xc9, 0x99, 0x7b,
                0x55, 0x1f, 0x24, 0x05, 0x1c, 0x35, 0x25, 0x67, 0xba, 0x6c, 0x01, 0xe5, 0x7a, 0xc7,
                0x5d, 0xff, 0x76, 0x3e, 0xaa, 0x17,
            ],
            [
                0x82, 0x70, 0x1e, 0xb9, 0x80, 0x70, 0x72, 0x8e, 0x17, 0x69, 0x52, 0x5e, 0x73, 0xab,
                0xff, 0x17, 0x83, 0xce, 0xdc, 0x36, 0x4a, 0xdb, 0x20, 0xc0, 0x5c, 0x89, 0x7a, 0x62,
                0xf2, 0xab, 0x29, 0x27, 0xf8, 0x6f, 0x11, 0x8d, 0xcb, 0x78, 0x19, 0xa7, 0xb2, 0x18,
                0xd8, 0xf3, 0xfe, 0xe4, 0xbd, 0x7f,
            ],
            [
                0xa1, 0xf2, 0x29, 0x54, 0x04, 0x74, 0xf4, 0xd6, 0xf1, 0x13, 0x47, 0x61, 0xb9, 0x2b,
                0x78, 0x81, 0x28, 0xc7, 0xac, 0x8d, 0xc9, 0xb0, 0xc5, 0x2d, 0x59, 0x49, 0x31, 0x32,
                0x67, 0x96, 0x73, 0x03, 0x2a, 0xc7, 0xdb, 0x3f, 0xb3, 0xd7, 0x9b, 0x46, 0xb1, 0x3c,
                0x1c, 0x41, 0xee, 0x49, 0x5b, 0xca,
            ],
        ];

        assert_eq!(generators[0].to_compressed(), q1);

        for (g, h) in generators[1..].iter().zip(expected_generators.iter()) {
            assert_eq!(g.to_compressed(), *h);
        }
    }

    #[test]
    fn bls12_381_sha256_messages_to_scalars_1() {
        let cs = BLS12_381_G1_XMD_SHA_256;

        let dst = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";
        let input = vec![M1, M2, M3, M4, M5, M6, M7, M8, M9, M10];
        let message_scalars = messages_to_scalars(&cs, &input, Some(dst));

        let mut msg_scalar_0 = [
            0x1c, 0xb5, 0xbb, 0x86, 0x11, 0x4b, 0x34, 0xdc, 0x43, 0x8a, 0x91, 0x16, 0x17, 0x65,
            0x5a, 0x1d, 0xb5, 0x95, 0xab, 0xaf, 0xac, 0x92, 0xf4, 0x7c, 0x50, 0x01, 0x79, 0x9c,
            0xf6, 0x24, 0xb4, 0x30,
        ];
        msg_scalar_0.reverse();
        let mut msg_scalar_1 = [
            0x15, 0x42, 0x49, 0xd5, 0x03, 0xc0, 0x93, 0xac, 0x2d, 0xf5, 0x16, 0xd4, 0xbb, 0x88,
            0xb5, 0x10, 0xd5, 0x4f, 0xd9, 0x7e, 0x8d, 0x71, 0x21, 0xae, 0xde, 0x42, 0x0a, 0x25,
            0xd9, 0x52, 0x19, 0x52,
        ];
        msg_scalar_1.reverse();
        let mut msg_scalar_2 = [
            0x0c, 0x7c, 0x4c, 0x85, 0xcd, 0xab, 0x32, 0xe6, 0xfd, 0xb0, 0xde, 0x26, 0x7b, 0x16,
            0xfa, 0x32, 0x12, 0x73, 0x3d, 0x4e, 0x3a, 0x3f, 0x0d, 0x0f, 0x75, 0x16, 0x57, 0x57,
            0x8b, 0x26, 0xfe, 0x22,
        ];
        msg_scalar_2.reverse();
        let mut msg_scalar_3 = [
            0x4a, 0x19, 0x6d, 0xea, 0xfe, 0xe5, 0xc2, 0x3f, 0x63, 0x01, 0x56, 0xae, 0x13, 0xbe,
            0x3e, 0x46, 0xe5, 0x3b, 0x7e, 0x39, 0x09, 0x4d, 0x22, 0x87, 0x7b, 0x8c, 0xba, 0x7f,
            0x14, 0x64, 0x08, 0x88,
        ];
        msg_scalar_3.reverse();
        let mut msg_scalar_4 = [
            0x34, 0xc5, 0xea, 0x4f, 0x2b, 0xa4, 0x91, 0x17, 0x01, 0x5a, 0x02, 0xc7, 0x11, 0xbb,
            0x17, 0x3c, 0x11, 0xb0, 0x6b, 0x3f, 0x15, 0x71, 0xb8, 0x8a, 0x29, 0x52, 0xb9, 0x3d,
            0x0e, 0xd4, 0xcf, 0x7e,
        ];
        msg_scalar_4.reverse();
        let mut msg_scalar_5 = [
            0x40, 0x45, 0xb3, 0x9b, 0x83, 0x05, 0x5c, 0xd5, 0x7a, 0x4d, 0x02, 0x03, 0xe1, 0x66,
            0x08, 0x00, 0xfa, 0xbe, 0x43, 0x40, 0x04, 0xdb, 0xdc, 0x87, 0x30, 0xc2, 0x1c, 0xe3,
            0xf0, 0x04, 0x8b, 0x08,
        ];
        msg_scalar_5.reverse();
        let mut msg_scalar_6 = [
            0x06, 0x46, 0x21, 0xda, 0x43, 0x77, 0xb6, 0xb1, 0xd0, 0x5e, 0xcc, 0x37, 0xcf, 0x3b,
            0x9d, 0xfc, 0x94, 0xb9, 0x49, 0x8d, 0x70, 0x13, 0xdc, 0x5c, 0x4a, 0x82, 0xbf, 0x3b,
            0xb1, 0x75, 0x07, 0x43,
        ];
        msg_scalar_6.reverse();
        let mut msg_scalar_7 = [
            0x34, 0xac, 0x91, 0x96, 0xac, 0xe0, 0xa3, 0x7e, 0x14, 0x7e, 0x32, 0x31, 0x9e, 0xa9,
            0xb3, 0xd8, 0xcc, 0x7d, 0x21, 0x87, 0x0d, 0x3c, 0x3b, 0xa0, 0x71, 0x24, 0x68, 0x59,
            0xcc, 0xa4, 0x9b, 0x02,
        ];
        msg_scalar_7.reverse();
        let mut msg_scalar_8 = [
            0x57, 0xeb, 0x93, 0xf4, 0x17, 0xc4, 0x32, 0x00, 0xe9, 0x78, 0x4f, 0xa5, 0xea, 0x5a,
            0x59, 0x16, 0x8d, 0x3d, 0xbc, 0x38, 0xdf, 0x70, 0x7a, 0x13, 0xbb, 0x59, 0x7c, 0x87,
            0x1b, 0x2a, 0x5f, 0x74,
        ];
        msg_scalar_8.reverse();
        let mut msg_scalar_9 = [
            0x08, 0xe3, 0xaf, 0xeb, 0x2b, 0x4f, 0x2b, 0x5f, 0x90, 0x79, 0x24, 0xef, 0x42, 0x85,
            0x66, 0x16, 0xe6, 0xf2, 0xd5, 0xf1, 0xfb, 0x37, 0x37, 0x36, 0xdb, 0x1c, 0xca, 0x32,
            0x70, 0x7a, 0x7d, 0x16,
        ];
        msg_scalar_9.reverse();

        assert_eq!(message_scalars[0].to_bytes(), msg_scalar_0);
        assert_eq!(message_scalars[1].to_bytes(), msg_scalar_1);
        assert_eq!(message_scalars[2].to_bytes(), msg_scalar_2);
        assert_eq!(message_scalars[3].to_bytes(), msg_scalar_3);
        assert_eq!(message_scalars[4].to_bytes(), msg_scalar_4);
        assert_eq!(message_scalars[5].to_bytes(), msg_scalar_5);
        assert_eq!(message_scalars[6].to_bytes(), msg_scalar_6);
        assert_eq!(message_scalars[7].to_bytes(), msg_scalar_7);
        assert_eq!(message_scalars[8].to_bytes(), msg_scalar_8);
        assert_eq!(message_scalars[9].to_bytes(), msg_scalar_9);
    }

    #[test]
    fn bls12_381_sha256_key_gen_1() {
        let cs = BLS12_381_G1_XMD_SHA_256;
        let key_material = [
            0x74, 0x68, 0x69, 0x73, 0x2d, 0x49, 0x53, 0x2d, 0x6a, 0x75, 0x73, 0x74, 0x2d, 0x61,
            0x6e, 0x2d, 0x54, 0x65, 0x73, 0x74, 0x2d, 0x49, 0x4b, 0x4d, 0x2d, 0x74, 0x6f, 0x2d,
            0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x2d, 0x24, 0x65, 0x28, 0x72, 0x40,
            0x74, 0x23, 0x2d, 0x6b, 0x65, 0x79,
        ];

        let key_info = [
            0x74, 0x68, 0x69, 0x73, 0x2d, 0x49, 0x53, 0x2d, 0x73, 0x6f, 0x6d, 0x65, 0x2d, 0x6b,
            0x65, 0x79, 0x2d, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2d, 0x74, 0x6f,
            0x2d, 0x62, 0x65, 0x2d, 0x75, 0x73, 0x65, 0x64, 0x2d, 0x69, 0x6e, 0x2d, 0x74, 0x65,
            0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x67, 0x65, 0x6e,
        ];

        let key_dst = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_KEYGEN_DST_";
        let key_dst_b = [
            0x42, 0x42, 0x53, 0x5f, 0x42, 0x4c, 0x53, 0x31, 0x32, 0x33, 0x38, 0x31, 0x47, 0x31,
            0x5f, 0x58, 0x4d, 0x44, 0x3a, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x5f, 0x53,
            0x53, 0x57, 0x55, 0x5f, 0x52, 0x4f, 0x5f, 0x48, 0x32, 0x47, 0x5f, 0x48, 0x4d, 0x32,
            0x53, 0x5f, 0x4b, 0x45, 0x59, 0x47, 0x45, 0x4e, 0x5f, 0x44, 0x53, 0x54, 0x5f,
        ];

        assert_eq!(key_dst, &key_dst_b);

        let sk = key_gen(&cs, &key_material, &key_info, Some(key_dst));

        let mut expected_sk = [
            0x60, 0xe5, 0x51, 0x10, 0xf7, 0x68, 0x83, 0xa1, 0x3d, 0x03, 0x0b, 0x2f, 0x6b, 0xd1,
            0x18, 0x83, 0x42, 0x2d, 0x5a, 0xbd, 0xe7, 0x17, 0x56, 0x9f, 0xc0, 0x73, 0x1f, 0x51,
            0x23, 0x71, 0x69, 0xfc,
        ];
        expected_sk.reverse();

        assert_eq!(sk.to_bytes(), expected_sk);

        let pk = sk_to_pk(&sk);

        let expected_pk = [
            0xa8, 0x20, 0xf2, 0x30, 0xf6, 0xae, 0x38, 0x50, 0x3b, 0x86, 0xc7, 0x0d, 0xc5, 0x0b,
            0x61, 0xc5, 0x8a, 0x77, 0xe4, 0x5c, 0x39, 0xab, 0x25, 0xc0, 0x65, 0x2b, 0xba, 0xa8,
            0xfa, 0x13, 0x6f, 0x28, 0x51, 0xbd, 0x47, 0x81, 0xc9, 0xdc, 0xde, 0x39, 0xfc, 0x9d,
            0x1d, 0x52, 0xc9, 0xe6, 0x02, 0x68, 0x06, 0x1e, 0x7d, 0x76, 0x32, 0x17, 0x1d, 0x91,
            0xaa, 0x8d, 0x46, 0x0a, 0xce, 0xe0, 0xe9, 0x6f, 0x1e, 0x7c, 0x4c, 0xfb, 0x12, 0xd3,
            0xff, 0x9a, 0xb5, 0xd5, 0xdc, 0x91, 0xc2, 0x77, 0xdb, 0x75, 0xc8, 0x45, 0xd6, 0x49,
            0xef, 0x3c, 0x4f, 0x63, 0xae, 0xbc, 0x36, 0x4c, 0xd5, 0x5d, 0xed, 0x0c,
        ];

        assert_eq!(pk, expected_pk);
    }

    #[test]
    fn bls12_381_sha256_hash_to_scalar_1() {
        let cs = BLS12_381_G1_XMD_SHA_256;
        let msg = [
            0x98, 0x72, 0xad, 0x08, 0x9e, 0x45, 0x2c, 0x7b, 0x6e, 0x28, 0x3d, 0xfa, 0xc2, 0xa8,
            0x0d, 0x58, 0xe8, 0xd0, 0xff, 0x71, 0xcc, 0x4d, 0x5e, 0x31, 0x0a, 0x1d, 0xeb, 0xdd,
            0xa4, 0xa4, 0x5f, 0x02,
        ];

        let dst = [
            0x42, 0x42, 0x53, 0x5f, 0x42, 0x4c, 0x53, 0x31, 0x32, 0x33, 0x38, 0x31, 0x47, 0x31,
            0x5f, 0x58, 0x4d, 0x44, 0x3a, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x5f, 0x53,
            0x53, 0x57, 0x55, 0x5f, 0x52, 0x4f, 0x5f, 0x48, 0x32, 0x47, 0x5f, 0x48, 0x4d, 0x32,
            0x53, 0x5f, 0x48, 0x32, 0x53, 0x5f,
        ];

        let result = hash_to_scalar(&cs, &msg, &dst);

        let mut bytes = [
            0x0f, 0x90, 0xcb, 0xee, 0x27, 0xbe, 0xb2, 0x14, 0xe6, 0x54, 0x5b, 0xec, 0xb8, 0x40,
            0x46, 0x40, 0xd3, 0x61, 0x2d, 0xa5, 0xd6, 0x75, 0x8d, 0xff, 0xec, 0xcd, 0x77, 0xed,
            0x71, 0x69, 0x80, 0x7c,
        ];
        bytes.reverse();

        assert_eq!(result.to_bytes(), bytes);
    }
}
