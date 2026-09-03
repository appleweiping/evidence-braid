# Research and deployment limitations

Evidence Braid combines confidence-bearing statements under an explicit policy. It does not learn
confidence calibration, infer causality, authenticate provenance, or determine truth.

The checked-in evaluation is synthetic. It provides a reproducible software experiment and useful
ablation baselines but no evidence about a real domain. Before operational use, an evaluator needs
a legally and ethically usable dataset from the target population, a prespecified labeling
procedure, inter-rater checks where labels are subjective, held-out policy selection, uncertainty
intervals, subgroup error analysis where appropriate, drift monitoring, and documented human
review. Consequential deployments require domain and legal review beyond this project.

Known methodological boundaries include:

- source reliabilities are static policy inputs rather than estimated distributions;
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
