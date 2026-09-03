# Project governance

The repository uses a maintainer-led, review-first model. Maintainers are responsible for release
signing and publishing, security response, compatibility decisions, and final review of decision
semantics. Contributors may propose changes through issues and pull requests and participate in
technical discussion under the Code of Conduct.

Changes to thresholds, aggregation, decay, correlation, replay semantics, schemas, metrics, or
security boundaries require a written problem statement, alternatives, compatibility analysis, and
tests. A maintainer should not merge a decision-semantics change based only on a benchmark number;
the underlying fixtures, labels, and failure cases must be reviewable.

Releases require a clean CI run, updated changelog and compatibility notes, regenerated golden
artifacts, built wheel and source distribution, and an isolated-wheel smoke test. Security reports
follow `SECURITY.md` and are coordinated privately before disclosure.

Governance can evolve as maintainership grows. Material changes to decision authority or release
control should be recorded here through normal review rather than made implicitly.
