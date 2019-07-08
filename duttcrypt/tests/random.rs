use std::time::{SystemTime, UNIX_EPOCH};
use duttcrypt::random::{untemper, MersenneTwister};

fn get_rng_val() -> u32 {
    let now = SystemTime::now();
    let timestamp = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    println!("{:?}", timestamp.as_secs() as u32);
    let mut rnd = MersenneTwister::new();
    rnd.seed(timestamp.as_secs() as u32);
    let randval = 40 + rnd.gen() as u64 % 1000;
    let seed = timestamp.as_secs() + randval;
    let mut rnd = MersenneTwister::new();
    println!("seed {:?}", seed);
    rnd.seed(seed as u32);
    rnd.gen()
}

fn get_rng_from_seed(seed : u32) -> u32 {
    let mut rng = MersenneTwister::new();
    rng.seed(seed);
    rng.gen()
}

#[test]
fn ch22_crack_seed() {
    let val = get_rng_val();
    let now = SystemTime::now();
    let timestamp = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let min = timestamp.as_secs();
    let max = timestamp.as_secs() + 1000;
    for i in min..max {
        if get_rng_from_seed(i as u32) == val {
            println!("found seed {:?}", i);
            break;
        }
    }
}

#[test]
fn ch23_clone_prng() {
    let mut rnd = MersenneTwister::new();
    rnd.seed(1);
    let mut origvals = Vec::new();
    for _ in 0..624 {
        origvals.push(rnd.gen());
    }
    let mut rnd2 = MersenneTwister::new();
    rnd2.seed(rnd.gen()); // random value, shouldn't matter
    rnd2.index = 0;
    for i in 0..624 {
        rnd2.mt[i] = untemper(origvals[i]);
    }
    let mut newvals = Vec::new();
    for _ in 0..624 {
        newvals.push(rnd2.gen());
    }
    assert_eq!(origvals, newvals);
}
