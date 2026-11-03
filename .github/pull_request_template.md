## What changed and why

<!-- Threat or gap covered, or the false positive being tuned. -->

## Checklist

- [ ] Fire and silent test cases cover the change
- [ ] `version` bumped for a changed rule, and `id` left unchanged
- [ ] `sdac catalog` run if rule metadata changed
- [ ] Query checked against real data in Log Analytics, including expected alert volume
