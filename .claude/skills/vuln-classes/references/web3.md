# Smart contracts and Web3

Use `web3-audit` / `web3_specialist` when the operator confirms a Web3 program
or supplies contract source for review. Check the program's current scope for
each contract/address and chain.

Review public entry points, roles, asset flows, external calls, oracle
assumptions, callbacks, upgrade controls, and protocol invariants. Suspicious
Solidity patterns and static code alone are candidates; quantify a reachable
state/value change before claiming impact.

No live transaction, deployment, fork-based PoC, or asset interaction is
implied by this route. Dynamic validation needs a separate authorized task and
an explicitly permitted test environment.
