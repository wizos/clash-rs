use std::net::IpAddr;

#[derive(Default)]
pub struct IpRangeSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpRangeSet {
    pub fn insert(&mut self, start: IpAddr, end: IpAddr) -> bool {
        match (normalize(start), normalize(end)) {
            (IpAddr::V4(start), IpAddr::V4(end)) if start <= end => {
                self.v4.push((start.into(), end.into()));
                true
            }
            (IpAddr::V6(start), IpAddr::V6(end)) if start <= end => {
                self.v6.push((start.into(), end.into()));
                true
            }
            _ => false,
        }
    }

    pub fn finalize(&mut self) {
        self.v4.sort_unstable();
        self.v6.sort_unstable();
        self.v4 = merge_v4(std::mem::take(&mut self.v4));
        self.v6 = merge_v6(std::mem::take(&mut self.v6));
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match normalize(ip) {
            IpAddr::V4(ip) => contains(&self.v4, u32::from(ip)),
            IpAddr::V6(ip) => contains(&self.v6, u128::from(ip)),
        }
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn contains<T: Ord + Copy>(ranges: &[(T, T)], value: T) -> bool {
    let index = ranges.partition_point(|(start, _)| *start <= value);
    index > 0 && value <= ranges[index - 1].1
}

fn merge_v4(ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some((_, previous_end)) = merged.last_mut()
            && start <= previous_end.saturating_add(1)
        {
            *previous_end = (*previous_end).max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

fn merge_v6(ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some((_, previous_end)) = merged.last_mut()
            && start <= previous_end.saturating_add(1)
        {
            *previous_end = (*previous_end).max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_and_queries_v4_v6_and_mapped_ranges() {
        let mut set = IpRangeSet::default();
        assert!(
            set.insert("10.0.0.1".parse().unwrap(), "10.0.0.3".parse().unwrap())
        );
        assert!(
            set.insert("10.0.0.4".parse().unwrap(), "10.0.0.9".parse().unwrap())
        );
        assert!(set.insert(
            "::ffff:192.0.2.1".parse().unwrap(),
            "::ffff:192.0.2.2".parse().unwrap()
        ));
        assert!(set.insert(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::5".parse().unwrap()
        ));
        assert!(
            !set.insert("10.0.0.2".parse().unwrap(), "2001:db8::2".parse().unwrap())
        );
        set.finalize();

        assert_eq!(set.len(), 3);
        assert!(set.contains("10.0.0.8".parse().unwrap()));
        assert!(set.contains("192.0.2.2".parse().unwrap()));
        assert!(set.contains("2001:db8::3".parse().unwrap()));
        assert!(!set.contains("10.0.0.10".parse().unwrap()));
    }
}
