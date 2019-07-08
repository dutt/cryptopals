#[derive(Debug)]
pub struct Constants {
    w: u32,
    n: usize,
    m: usize,
    r: u32,
    a: u32,
    pub u: u32,
    pub d: u32,
    pub s: u32,
    pub b: u32,
    pub t: u32,
    pub c: u32,
    pub l: u32,
    f: u32,
}

pub static CONSTANTS : Constants = Constants {
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
pub struct MersenneTwister {
    pub mt : Vec<u32>,
    pub index : usize,
    lower_mask : u32,
    upper_mask : u32,
}

impl MersenneTwister {
    pub fn new() -> MersenneTwister {
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
    pub fn seed(&mut self, seed : u32) {
        self.index = CONSTANTS.n;
        self.mt[0] = seed;
        for i in 1..(CONSTANTS.n) {
            self.mt[i] = 0xFFFFFFFF &
                            (u32::overflowing_mul(CONSTANTS.f,
                                 self.mt[i-1] ^
                                (self.mt[i-1] >> (CONSTANTS.w - 2))).0
                            + i as u32);
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
    pub fn gen(&mut self) -> u32 {
        if self.index >= CONSTANTS.n {
            self.twist();
        }
        let y1 = self.mt[self.index];
        let y2 = y1 ^ ((y1 >> CONSTANTS.u) & CONSTANTS.d);
        let y3 = y2 ^ ((y2 << CONSTANTS.s) & CONSTANTS.b);
        let y4 = y3 ^ ((y3 << CONSTANTS.t) & CONSTANTS.c);
        let y5 = y4 ^ (y4 >> CONSTANTS.l);
        self.index += 1;
        //println!("y1 {} y1bin {:0>32b}", y1, y1);
        //println!("y2 {} y2bin {:0>32b}", y2, y2);
        //println!("y3 {} y3bin {:0>32b}", y3, y3);
        //println!("y4 {} y4bin {:0>32b}", y4, y4);
        //println!("y5 {} y5bin {:0>32b}", y5, y5);
        y5 & 0xFFFFFFFF
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

fn untemper_rs(val : u32, shift_by : u32) -> u32 {
    let mut retr = val;
    let mut tmp = val;
    for _i in 0..=32 / shift_by {
        //println!("i {:?} parts {}", _i, 32 / shift_by);
        //println!("tmp {} tmpbin {:0>32b}", tmp, tmp);
        tmp >>= shift_by;
        //println!("shifted tmp {} stmpbin {:0>32b}", tmp, tmp);
        //println!("retr {} retrbin {:0>32b}", retr, retr);
        retr ^= tmp;
        //println!("xored retr {} retrbin {:0>32b}", retr, retr);
    }
    retr
}
fn untemper_lsa(val : u32, shift_by : u32, and_with : u32) -> u32 {
    let mut retr = val;
    for _ in 0..=32 / shift_by {
        retr = val ^ ((retr << shift_by) & and_with);
    }
    retr
}

pub fn untemper(y : u32) -> u32 {
    // println!("\ny {} ybin {:0>32b}\n", y, y);

    // y4 := y3 xor (y3 >> l)
    let y3 = untemper_rs(y, CONSTANTS.l);
    // println!("xy3 {:?} xy3 {:0>32b}", y3, y3);

    // y3 := y2 xor ((y2 << t) and c)
    let y2 = untemper_lsa(y3, CONSTANTS.t, CONSTANTS.c);
    // println!("xy2 {:?} xy2 {:0>32b}", y2, y2);

    // y2 := y1 xor ((y1 << s) and b)
    let y1 = untemper_lsa(y2, CONSTANTS.s, CONSTANTS.b);
    // println!("xy1 {:?} xy1 {:0>32b}", y1, y1);

    // y1 := y0 xor ((y0 >> u) and d)
    let y0 = untemper_rs(y1, CONSTANTS.u);
    // println!("xy0 {:?} xy0 {:0>32b}", y0, y0);

    y0
}
