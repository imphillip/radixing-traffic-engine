# Third-party notices

Radixing TDS source code is MIT licensed. Downloaded data and installed dependencies have independent licenses. They are not relicensed by this project. Dependencies are installed separately and include their original license files; preserve them when distributing a bundled application.

## Runtime dependencies

| Dependency | Copyright / license |
| --- | --- |
| Bowser 2.14.1 | Copyright 2015 Dustin Diaz; MIT-labelled license with an additional modified-distribution contact requirement. See `node_modules/bowser/LICENSE`. |
| csv-parse 7.0.3 | Copyright 2010 Adaltas; MIT. See `node_modules/csv-parse/LICENSE`. |
| ipaddr.js 2.5.0 | Copyright 2011-2017 whitequark; MIT. See `node_modules/ipaddr.js/LICENSE`. |
| RE2JS 2.8.6 | Copyright 2023 Oleksii Vasyliev; MIT. See `node_modules/re2js/LICENSE`; preserve notices of upstream code when bundling. |
| structured-headers 2.0.3 | Copyright 2018-2025 Evert Pot; MIT. See `node_modules/structured-headers/LICENSE`. |

These packages are used without vendoring or modification. Development tools retain their original package licenses as well. The exact dependency tree is recorded in `package-lock.json`.

## Downloaded datasets

- [IPtoASN](https://iptoasn.com/): Public Domain Dedication and License (PDDL 1.0), as stated by its maintainer. [License](https://opendatacommons.org/licenses/pddl/1-0/).
- [X4B lists_vpn](https://github.com/X4BNet/lists_vpn): MIT, Copyright 2024 X4B (Mathew Heard), covering scripts, source and generated output. Preserve its copyright/permission notice when redistributing data.
- [crawler-user-agents](https://github.com/monperrus/crawler-user-agents): MIT; preserve its [license](https://github.com/monperrus/crawler-user-agents/blob/master/LICENSE) when redistributing data.
- [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite), optional: CC BY 4.0 with DB-IP attribution and its stated web link-back requirement. [License](https://creativecommons.org/licenses/by/4.0/).

No downloaded dataset is included in this repository or release package. Operators obtain datasets directly and remain responsible for attribution and redistribution requirements. Each local snapshot retains source URL and license metadata. Review current upstream terms before changing sources or redistribution arrangements.
