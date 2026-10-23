//! Small sorts. core's sorts are fast on big slices but each element type gets
//! its own copy of several KB; the kernel and the boot module sort short lists
//! (modules, addresses, file names), where a shell sort is a few hundred
//! bytes. Not stable: equal elements may change order.

/// Sorts `v` so that no element is `lt` the one before it.
pub fn sort_by<T>(v: &mut [T], mut lt: impl FnMut(&T, &T) -> bool) {
    // Ciura's gaps, extended by x2.25 for long slices
    let mut gaps = [1usize, 4, 10, 23, 57, 132, 301, 701, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut n = 8;
    while n < gaps.len() && gaps[n - 1] < v.len() / 2 {
        gaps[n] = gaps[n - 1] * 9 / 4;
        n += 1;
    }
    for &g in gaps[..n].iter().rev() {
        for i in g..v.len() {
            let mut j = i;
            while j >= g && lt(&v[j], &v[j - g]) {
                v.swap(j, j - g);
                j -= g;
            }
        }
    }
}

/// Sorts `v` in ascending order.
pub fn sort<T: Ord>(v: &mut [T]) {
    sort_by(v, |a, b| a < b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts() {
        for n in [0usize, 1, 2, 5, 100, 5000] {
            let mut x = 12345u32;
            let mut v: alloc::vec::Vec<u32> = (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x % 1000
                })
                .collect();
            let mut want = v.clone();
            want.sort();
            sort(&mut v);
            assert_eq!(v, want);
        }
    }
}
