# Security

## Reporting a problem in uplift

If the checker, the report writer, or the way a snapshot is read can be made to do something it should not, report it in private:

[Open a GitHub security advisory](https://github.com/WastedPatriot/uplift/security/advisories/new)

Please do not file a public issue for an unfixed hole. Say what you ran, what you expected, and what happened. A snapshot that shows the problem is worth more than a long story.

A finding on a lab machine is the tool working. That belongs with the person who owns the host, not here.

## Authorised use

Run uplift only on hosts you are allowed to assess. It records misconfigurations and their impact. It does not exploit them. Pointing it at someone else's server is not a defect in this repository, and it will not become one because the report looked official.

## What is supported

`main` is the supported line. Older commits are history, not a maintenance promise.
