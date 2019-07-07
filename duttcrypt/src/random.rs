#[derive(Debug)]
struct Constants {
    w: u32,
    n: usize,
    m: usize,
    r: u32,
    a: u32,
    u: u32,
    d: u32,
    s: u32,
    b: u32,
    t: u32,
    c: u32,
    l: u32,
    f: u32,
}

static CONSTANTS : Constants = Constants {
    w : 32,
    n : 624,
    m : 397,
    r : 31,
    a : 0x9908B0DF,
    u : 11,
    d : 0xFFFFFFFF,
    s : 7,
    b : 0x9D2C5680,
    t : 15,
    c : 0xEFC60000,
    l : 18,
    f : 1812433253,
};

#[derive(Debug)]
struct MersenneTwister {
    mt : Vec<u32>,
    index : usize,
    lower_mask : u32,
    upper_mask : u32,
}

impl MersenneTwister {
    fn new() -> MersenneTwister {
        let lower_mask = (1 << CONSTANTS.r) - 1;
        let upper_mask = !lower_mask & 0xFFFFFFFF;
        MersenneTwister {
            mt : vec![0; CONSTANTS.n],
            index : CONSTANTS.n + 1,
            lower_mask : lower_mask,
            upper_mask : upper_mask,
        }
    }

    /*
     function seed_mt(int seed) {
         index := n
         MT[0] := seed
         for i from 1 to (n - 1) { // loop over each element
             MT[i] := lowest w bits of
                            (f *
                                (MT[i-1] xor
                                (MT[i-1] >> (w-2)))
                            + i)
         }
     }
    */
    fn seed(&mut self, seed : u32) {
        self.index = CONSTANTS.n;
        self.mt[0] = seed;
        for i in 1..(CONSTANTS.n) {
            self.mt[i] = 0xFFFFFFFF &
                            (u32::overflowing_mul(CONSTANTS.f,
                                 self.mt[i-1] ^
                                (self.mt[i-1] >> (CONSTANTS.w - 2))).0
                            + i as u32);
            //println!("i={}, overflow={}, tot={}", i,
            //                            u32::overflowing_mul(CONSTANTS.f,
            //                                                   self.mt[i-1] ^
            //                                                   (self.mt[i-1] >> (CONSTANTS.w - 2))).0,
            //                            self.mt[i]);
        }
    }

    /*
     function extract_number() {
         if index >= n {
             twist()
         }

         int y := MT[index]
         y := y xor ((y >> u) and d)
         y := y xor ((y << s) and b)
         y := y xor ((y << t) and c)
         y := y xor (y >> l)

         index := index + 1
         return lowest w bits of (y)
     }
    */
    fn gen(&mut self) -> u32 {
        if self.index >= CONSTANTS.n {
            self.twist();
        }
        let mut y = self.mt[self.index];
        y = y ^ ((y >> CONSTANTS.u) & CONSTANTS.d);
        y = y ^ ((y << CONSTANTS.s) & CONSTANTS.b);
        y = y ^ ((y << CONSTANTS.t) & CONSTANTS.c);
        y = y ^ (y >> CONSTANTS.l);
        self.index += 1;
        y & 0xFFFFFFFF
    }
    /*
     function twist() {
         for i from 0 to (n-1) {
             int x := (MT[i] and upper_mask)
                       + (MT[(i+1) mod n] and lower_mask)
             int xA := x >> 1
             if (x mod 2) != 0 { // lowest bit of x is 1
                 xA := xA xor a
             }
             MT[i] := MT[(i + m) mod n] xor xA
         }
         index := 0
     }
    */
    fn twist(&mut self) {
        for i in 0..CONSTANTS.n {
            let x = (self.mt[i] & self.upper_mask) +
                    (self.mt[(i+1) % CONSTANTS.n] & self.lower_mask);
            self.mt[i] = self.mt[(i + CONSTANTS.m) % CONSTANTS.n] ^ (x >> 1);
            if (x % 2) != 0 {
                self.mt[i] = self.mt[i] ^ CONSTANTS.a;
            }
        }
        self.index = 0;
    }
}
