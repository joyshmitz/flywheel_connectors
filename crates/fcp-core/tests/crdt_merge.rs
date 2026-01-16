use fcp_core::{CrdtActorId, GCounter, LwwMap, OrSet, OrSetTag, PnCounter};

#[test]
fn lww_map_picks_latest_timestamp() {
    let mut map = LwwMap::default();
    map.insert("k".to_string(), "v1".to_string(), 10, CrdtActorId::new("a"));
    map.insert("k".to_string(), "v2".to_string(), 20, CrdtActorId::new("b"));

    let entry = map.get(&"k".to_string()).expect("entry exists");
    assert_eq!(entry.value, "v2");
    assert_eq!(entry.timestamp, 20);
}

#[test]
fn lww_map_tie_breaks_by_actor_id() {
    let mut map = LwwMap::default();
    map.insert("k".to_string(), "v1".to_string(), 10, CrdtActorId::new("a"));
    map.insert("k".to_string(), "v2".to_string(), 10, CrdtActorId::new("b"));

    let entry = map.get(&"k".to_string()).expect("entry exists");
    assert_eq!(entry.value, "v2");
    assert_eq!(entry.actor.as_str(), "b");
}

#[test]
fn orset_add_remove_merge() {
    let mut left = OrSet::default();
    let mut right = OrSet::default();

    let tag_left = OrSetTag::new(CrdtActorId::new("actor-1"), 1);
    let tag_right = OrSetTag::new(CrdtActorId::new("actor-1"), 1);
    left.add("item".to_string(), tag_left);
    assert!(left.contains(&"item".to_string()));

    right.add("item".to_string(), tag_right);
    right.remove_observed(&"item".to_string());
    assert!(!right.contains(&"item".to_string()));

    left.merge(&right);
    assert!(!left.contains(&"item".to_string()));
}

#[test]
fn orset_remove_does_not_clear_other_adds() {
    let mut set = OrSet::default();
    set.add("item".to_string(), OrSetTag::new(CrdtActorId::new("a"), 1));
    set.add("item".to_string(), OrSetTag::new(CrdtActorId::new("b"), 1));
    set.remove_observed(&"item".to_string());

    // All observed adds were removed, so the value is absent.
    assert!(!set.contains(&"item".to_string()));

    // Re-add from a new actor tag should bring it back.
    set.add("item".to_string(), OrSetTag::new(CrdtActorId::new("c"), 1));
    assert!(set.contains(&"item".to_string()));
}

#[test]
fn gcounter_merges_by_max() {
    let mut left = GCounter::default();
    left.increment(CrdtActorId::new("a"), 3);

    let mut right = GCounter::default();
    right.increment(CrdtActorId::new("a"), 5);
    right.increment(CrdtActorId::new("b"), 2);

    left.merge(&right);
    assert_eq!(left.value(), 7);
}

#[test]
fn pncounter_merge_and_value() {
    let mut left = PnCounter::default();
    left.increment(CrdtActorId::new("a"), 5);
    left.decrement(CrdtActorId::new("a"), 1);

    let mut right = PnCounter::default();
    right.increment(CrdtActorId::new("a"), 3);
    right.decrement(CrdtActorId::new("b"), 2);

    left.merge(&right);
    assert_eq!(left.value(), 5 - 1 - 2);
}

// =============================================================================
// LwwMap cross-replica merge tests
// =============================================================================

#[test]
fn lww_map_merge_disjoint_keys() {
    let mut replica_a: LwwMap<String, String> = LwwMap::default();
    replica_a.insert(
        "key1".into(),
        "value1".into(),
        100,
        CrdtActorId::new("node-a"),
    );

    let mut replica_b: LwwMap<String, String> = LwwMap::default();
    replica_b.insert(
        "key2".into(),
        "value2".into(),
        100,
        CrdtActorId::new("node-b"),
    );

    // Merge B into A
    replica_a.merge(&replica_b);

    // Both keys should exist
    assert_eq!(replica_a.get(&"key1".into()).unwrap().value, "value1");
    assert_eq!(replica_a.get(&"key2".into()).unwrap().value, "value2");
}

#[test]
fn lww_map_merge_same_key_newer_wins() {
    let mut replica_a: LwwMap<String, String> = LwwMap::default();
    replica_a.insert(
        "cursor".into(),
        "offset-100".into(),
        100,
        CrdtActorId::new("node-a"),
    );

    let mut replica_b: LwwMap<String, String> = LwwMap::default();
    replica_b.insert(
        "cursor".into(),
        "offset-200".into(),
        200,
        CrdtActorId::new("node-b"),
    );

    // Merge B into A - B's newer timestamp should win
    replica_a.merge(&replica_b);
    assert_eq!(replica_a.get(&"cursor".into()).unwrap().value, "offset-200");
    assert_eq!(replica_a.get(&"cursor".into()).unwrap().timestamp, 200);

    // Merge in other direction: A into B - same result
    let mut replica_a2: LwwMap<String, String> = LwwMap::default();
    replica_a2.insert(
        "cursor".into(),
        "offset-100".into(),
        100,
        CrdtActorId::new("node-a"),
    );
    replica_b.merge(&replica_a2);
    assert_eq!(replica_b.get(&"cursor".into()).unwrap().value, "offset-200");
}

#[test]
fn lww_map_merge_same_key_same_timestamp_actor_tiebreak() {
    let mut replica_a: LwwMap<String, String> = LwwMap::default();
    replica_a.insert(
        "sync_token".into(),
        "token-a".into(),
        500,
        CrdtActorId::new("actor-a"),
    );

    let mut replica_b: LwwMap<String, String> = LwwMap::default();
    replica_b.insert(
        "sync_token".into(),
        "token-z".into(),
        500,
        CrdtActorId::new("actor-z"),
    );

    // Same timestamp - actor "z" > "a" lexicographically, so token-z wins
    replica_a.merge(&replica_b);
    assert_eq!(
        replica_a.get(&"sync_token".into()).unwrap().value,
        "token-z"
    );
    assert_eq!(
        replica_a.get(&"sync_token".into()).unwrap().actor.as_str(),
        "actor-z"
    );
}

#[test]
fn lww_map_merge_preserves_existing_if_newer() {
    let mut replica_a: LwwMap<String, String> = LwwMap::default();
    replica_a.insert("key".into(), "newer".into(), 1000, CrdtActorId::new("a"));

    let mut replica_b: LwwMap<String, String> = LwwMap::default();
    replica_b.insert("key".into(), "older".into(), 500, CrdtActorId::new("b"));

    // Merging older data should not overwrite
    replica_a.merge(&replica_b);
    assert_eq!(replica_a.get(&"key".into()).unwrap().value, "newer");
    assert_eq!(replica_a.get(&"key".into()).unwrap().timestamp, 1000);
}

#[test]
fn lww_map_merge_bidirectional_converges() {
    // Two replicas with concurrent updates to different keys
    let mut replica_a: LwwMap<String, i32> = LwwMap::default();
    replica_a.insert("poll_cursor".into(), 100, 10, CrdtActorId::new("a"));
    replica_a.insert("retry_count".into(), 3, 15, CrdtActorId::new("a"));

    let mut replica_b: LwwMap<String, i32> = LwwMap::default();
    replica_b.insert("poll_cursor".into(), 200, 20, CrdtActorId::new("b"));
    replica_b.insert("last_error".into(), 404, 18, CrdtActorId::new("b"));

    // Merge both ways
    let mut merged_from_a = replica_a.clone();
    merged_from_a.merge(&replica_b);

    let mut merged_from_b = replica_b.clone();
    merged_from_b.merge(&replica_a);

    // Both should converge to same state
    assert_eq!(merged_from_a.get(&"poll_cursor".into()).unwrap().value, 200); // B's is newer
    assert_eq!(merged_from_a.get(&"retry_count".into()).unwrap().value, 3); // Only in A
    assert_eq!(merged_from_a.get(&"last_error".into()).unwrap().value, 404); // Only in B

    assert_eq!(merged_from_b.get(&"poll_cursor".into()).unwrap().value, 200);
    assert_eq!(merged_from_b.get(&"retry_count".into()).unwrap().value, 3);
    assert_eq!(merged_from_b.get(&"last_error".into()).unwrap().value, 404);
}

// =============================================================================
// OrSet additional merge scenarios
// =============================================================================

#[test]
fn orset_concurrent_add_survives_partial_remove() {
    // Simulate: A adds item, B independently adds same item, then A removes
    let mut replica_a: OrSet<String> = OrSet::default();
    let tag_a = OrSetTag::new(CrdtActorId::new("a"), 1);
    replica_a.add("file.txt".into(), tag_a);

    let mut replica_b: OrSet<String> = OrSet::default();
    let tag_b = OrSetTag::new(CrdtActorId::new("b"), 1);
    replica_b.add("file.txt".into(), tag_b);

    // A removes its own observed tags
    replica_a.remove_observed(&"file.txt".into());
    assert!(!replica_a.contains(&"file.txt".into()));

    // Now merge B into A - B's add should make item present again
    replica_a.merge(&replica_b);
    assert!(replica_a.contains(&"file.txt".into()));
}

#[test]
fn orset_merge_commutative() {
    let mut a: OrSet<String> = OrSet::default();
    a.add("x".into(), OrSetTag::new(CrdtActorId::new("n1"), 1));

    let mut b: OrSet<String> = OrSet::default();
    b.add("y".into(), OrSetTag::new(CrdtActorId::new("n2"), 1));

    let mut c: OrSet<String> = OrSet::default();
    c.add("x".into(), OrSetTag::new(CrdtActorId::new("n3"), 1));
    c.remove_observed(&"x".into());

    // Merge order: a <- b <- c
    let mut result1 = a.clone();
    result1.merge(&b);
    result1.merge(&c);

    // Merge order: a <- c <- b
    let mut result2 = a.clone();
    result2.merge(&c);
    result2.merge(&b);

    // Both should have same membership
    assert!(result1.contains(&"y".into()));
    assert!(result2.contains(&"y".into()));
    // x should be present in result1 due to a's unremoved tag, absent for c's tag
    assert!(result1.contains(&"x".into())); // a's tag survives
    assert!(result2.contains(&"x".into())); // same
}

// =============================================================================
// GCounter edge cases
// =============================================================================

#[test]
fn gcounter_merge_idempotent() {
    let mut a = GCounter::default();
    a.increment(CrdtActorId::new("x"), 5);

    let b = a.clone();
    a.merge(&b);
    a.merge(&b);
    a.merge(&b);

    // Should still be 5, not 20
    assert_eq!(a.value(), 5);
}

#[test]
fn gcounter_saturating_add() {
    let mut counter = GCounter::default();
    counter.increment(CrdtActorId::new("a"), u64::MAX);
    counter.increment(CrdtActorId::new("a"), 1);
    // Should saturate, not wrap
    assert_eq!(
        *counter.counts.get(&CrdtActorId::new("a")).unwrap(),
        u64::MAX
    );
}
