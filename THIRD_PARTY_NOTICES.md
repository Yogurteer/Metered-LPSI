# Third-party source and licensing

This release contains third-party source. The following licenses apply to the respective components, not to the whole repository.

| Included source | Upstream | License text |
| --- | --- | --- |
| `code/apsi` | https://github.com/microsoft/APSI | MIT, `code/apsi/LICENSE` |
| `code/metered-lpsi/PIRANA` | https://github.com/zju-abclab/PIRANA | MIT, `code/metered-lpsi/PIRANA/LICENSE` |
| `code/ppsi` | https://github.com/alibaba-edu/mpc4j, Payable PSI/PIR module | Apache-2.0, `code/ppsi/LICENSE` |

The PIRANA license was retrieved from upstream revision `073eb1bf1d043d4909b3cb5e905e8545c56f7227`; this identifies the license source, not a claim that the included adapted source is byte-identical to that revision. The MPC4J license was retrieved from tag `v1.1.4-beta`; no NOTICE file was found in that upstream tag's tree. Retain existing third-party copyright and author notices.

Local adaptations include the Metered-LPSI PIRANA integration and build/packaging instructions. The included sources are not asserted to be pristine upstream snapshots. See `code/ppsi/MODIFICATIONS.md` for the file-level comparison with the documented upstream tag.

External dependencies (SEAL, Kuku, libOTe and its dependencies, OpenSSL, Boost, and Cargo-resolved Rust crates) are installed separately and retain their own licenses. This source release does not bundle their compiled outputs. Redistributing compiled artifacts or vendoring those dependencies requires retaining their applicable license and attribution material as well.

No repository-wide license has been selected for the original Metered-LPSI code. Its copyright holders must choose and authorize any additional license grant. This notice grants no additional rights and does not limit third-party license rights.
