# Research and deployment limitations

Evidence Braid combines confidence-bearing statements under an explicit policy. It does not learn
confidence calibration, infer causality, authenticate provenance, or determine truth. Where a
policy opts into reliability updating, ground truth is an input the caller supplies, not something
the engine discovers: it applies a stated arithmetic rule to judgements someone else made.

The checked-in evaluation is synthetic. It provides a reproducible software experiment and useful
ablation baselines but no evidence about a real domain. Before operational use, an evaluator needs
a legally and ethically usable dataset from the target population, a prespecified labeling
procedure, inter-rater checks where labels are subjective, held-out policy selection, uncertainty
intervals, subgroup error analysis where appropriate, drift monitoring, and documented human
review. Consequential deployments require domain and legal review beyond this project.

Known methodological boundaries include:

- source reliabilities are static policy inputs unless a policy opts into the documented update
  rule, which is a fixed weighted average over counted, caller-supplied adjudications rather than
  an estimated distribution: it has no posterior interval, no calibration guarantee, and no claim
  to converge on a true reliability;
- an updated reliability is only as good as the adjudications behind it. Judgement coverage is
  usually neither complete nor random — cases that get reviewed are often the ones that already
  looked wrong — so a counted correct rate can be a biased estimate of a source's real one. The
  engine makes the arithmetic reproducible and auditable; it cannot make a biased sample
  representative;
- event confidence is accepted as supplied and may be miscalibrated;
- declared correlation groups can be missing, wrong, or adversarial;
- noisy-or aggregation is a policy heuristic, not a generative probability model;
- one event carries one binary signal about one claim;
- review is an abstention outcome, but the project does not optimize a cost-sensitive review policy;
- fixed-width ECE is sample- and bin-dependent;
- benchmark timing excludes storage, authentication, transport, upstream inference, operator work,
  and contention from a production service.

Results should state the exact version, policy, dataset provenance, label definition, evaluation
time semantics, metric protocol, and hardware. Synthetic results must remain labeled synthetic.
