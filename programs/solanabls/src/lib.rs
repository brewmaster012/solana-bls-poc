use anchor_lang::prelude::*;

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, PrimeGroup,
};
use ark_ff::BigInteger;
use ark_ff::{BigInteger256, Field, PrimeField, Zero};
use ark_std::ops::Mul;
use num_bigint::BigUint;
use rust_bls_bn254::{hash_to_curve, key_gen, sign, verify};
// use solana_sdk::big_mod_exp::big_mod_exp;
use ark_std::One;
use hex::decode;
use num_traits::Num;
use solana_program::alt_bn128::prelude::*;
use solana_program::big_mod_exp::big_mod_exp;
use tiny_keccak::{Hasher, Keccak};
declare_id!("55q9EhHs3kVsH3dZKbBojec9ao1kJb56g1D7jLoNyCEp");

fn FqFromBigUint(n: BigUint) -> Fq {
    let mut bytes = [0u8; 32];
    n.to_bytes_be()
        .iter()
        .rev()
        .enumerate()
        .for_each(|(i, &b)| bytes[i] = b);
    Fq::from_le_bytes_mod_order(&bytes)
}

#[program]
pub mod solanabls {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }

    pub fn compute(ctx: Context<Compute>, n: u64) -> Result<()> {
        let one = Fq::one();
        let three = Fq::from(3u64);

        let message = "Hello BLS".as_bytes();
        let mut hasher = Keccak::v256();
        hasher.update(message);
        let mut hashed_result = [0u8; 32];
        hasher.finalize(&mut hashed_result);
        msg!("hashed: {:?}", hashed_result);
        let big_int = BigUint::from_bytes_be(&hashed_result);

        let x = FqFromBigUint(big_int);
        let mut y = x;
        y.square_in_place();
        y *= x;
        y += three;

        let q_bytes =
            decode("0c19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52").unwrap();
        let q = BigUint::from_bytes_be(&q_bytes);
        let p = BigUint::from_str_radix(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
            10,
        )
        .unwrap();
        msg!("q= {:?}", q);
        msg!("p= {:?}", p);
        msg!("y= {}", y);

        let y_bytes = y.into_bigint().to_bytes_be();

        let y2_bytes = big_mod_exp(
            y_bytes.as_slice(),
            q_bytes.as_slice(),
            p.to_bytes_be().as_slice(),
        );
        let y2 = BigUint::from_bytes_be(&y2_bytes);
        msg!("y2= {}", y2);
        let y2Fq = FqFromBigUint(y2);
        let y22 = y2Fq.square();
        msg!("y = y2*y2?  {}", y22 == y);
        let hash_point = G1Projective::new(x, y2Fq, Fq::one()).into_affine();
        msg!("hashPoint: {:?} {:?}", hash_point.x, hash_point.y);
        // now sign: secretkey * message hash
        let sk_int = BigUint::from_str_radix(
            "5532719355993668376817313988550233634227690018686483329169046691728862458102",
            10,
        )
        .unwrap();
        // fill the first 32 bytes of input with the hash_point.x in big endian
        // fill the second 32 bytes of input with the hash_point.y in big endian
        // fill the third 32 bytes of input with the sk_int in big endian
        let x_bytes = hash_point.x.into_bigint().to_bytes_be();
        let y_bytes = hash_point.y.into_bigint().to_bytes_be();
        let sk_bytes = sk_int.to_bytes_be();
        let mut input = [0u8; 96];
        for i in 0..32 {
            input[i] = x_bytes[i];
            input[i + 32] = y_bytes[i];
            input[i + 64] = sk_bytes[i];
        }
        let sig = alt_bn128_multiplication(input.as_slice()).unwrap();
        msg!("sig: {:?}", sig.len());
        let sigx = BigUint::from_bytes_be(&sig[..32]);
        let sigy = BigUint::from_bytes_be(&sig[32..64]);
        msg!("sigx: {:?}", sigx);
        msg!("sigy: {:?}", sigy);

        // now let's try to verify signature...
        // alt_bn128_pairing();
        let nG2x1 = BigUint::from_str_radix(
            "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            10,
        )
        .unwrap()
        .to_bytes_be();
        let nG2x0 = BigUint::from_str_radix(
            "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            10,
        )
        .unwrap()
        .to_bytes_be();
        let nG2y1 = BigUint::from_str_radix(
            "17805874995975841540914202342111839520379459829704422454583296818431106115052",
            10,
        )
        .unwrap()
        .to_bytes_be();
        let nG2y0 = BigUint::from_str_radix(
            "13392588948715843804641432497768002650278120570034223513918757245338268106653",
            10,
        )
        .unwrap()
        .to_bytes_be();
        let pkx0 = BigUint::from_str_radix(
            "8378816085881533471915855765377395720650519250900991714910570838142371337484",
            10,
        )
        .unwrap()
        .to_bytes_be();
        let pkx1 = BigUint::from_str_radix(
            "12790415566273137204438980474676206431551668194861774000289116208318672938344",
            10,
        )
        .unwrap()
        .to_bytes_be();
        let pky0 = BigUint::from_str_radix(
            "19990703290207056186001361313522144773565207870437521135189959374985874088302",
            10,
        )
        .unwrap()
        .to_bytes_be();
        let pky1 = BigUint::from_str_radix(
            "4358342334887501838847343362140356079440147357795966237968340896425437333463",
            10,
        )
        .unwrap()
        .to_bytes_be();
        let mut input2 = [0u8; 384];
        // fill the first 64 bytes of input with sig
        // fill the second 4x32 bytes of input with nG2x1, nG2x0, nG2y1, nG2y0
        // fill the next 64 bytes of input with pk
        // fill the last 4x32 bytes of input with pkx1, pkx0, pky1, pky0
        let hx = hash_point.x.into_bigint().to_bytes_be();
        let hy = hash_point.y.into_bigint().to_bytes_be();
        for i in 0..32 {
            input2[i] = sig[i];
            input2[i + 32] = sig[i + 32];
            input2[i + 64] = nG2x1[i];
            input2[i + 96] = nG2x0[i];
            input2[i + 128] = nG2y1[i];
            input2[i + 160] = nG2y0[i];
            input2[i + 192] = hx[i];
            input2[i + 224] = hy[i];
            // input2[i + 192] = sig[i];
            // input2[i + 224] = sig[i + 32];
            input2[i + 256] = pkx1[i];
            input2[i + 288] = pkx0[i];
            input2[i + 320] = pky1[i];
            input2[i + 352] = pky0[i];
        }
        let res = alt_bn128_pairing(input2.as_slice()).unwrap();
        msg!("res: {:?}", res[31]);

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}

#[derive(Accounts)]
pub struct Compute {}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::G2Projective;
    use ark_ec::AdditiveGroup;
    use ark_ff::UniformRand;
    use ark_std::{ops::Mul, test_rng};
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn test_generic() {
        let sk_str = "5532719355993668376817313988550233634227690018686483329169046691728862458102";
        let sk_bigint = BigUint::from_str_radix(sk_str, 10).unwrap();
        let bytes = sk_bigint.to_bytes_le();
        assert!(bytes.len() == 32, "size of sk bytes should be 256");
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks(8).enumerate().take(4) {
            let mut limb_bytes = [0u8; 8];
            // Copy each chunk into an 8-byte array (zero-padding if necessary).
            for (j, b) in chunk.iter().enumerate() {
                limb_bytes[j] = *b;
            }
            limbs[i] = u64::from_le_bytes(limb_bytes);
        }
        let bigint = BigInteger256::new(limbs);

        println!("reconstructed bigint256 sk: {}", bigint);
        let sk = Fr::new(bigint);
        println!("reconstructed Fr sk: {}", sk);

        let pubkey = G2Projective::from(G2Affine::generator())
            .mul(sk)
            .into_affine();
        println!("pubkey: {:?}", pubkey);

        let message = "Hello BLS".as_bytes();
        let hashed = hash_to_curve(message);
        println!("hashed: {:?}", hashed);

        let sig = sign(sk, &message.to_vec()).unwrap();

        let res = verify(pubkey, &message.to_vec(), sig);
        assert!(res, "verify failed");
    }
}
