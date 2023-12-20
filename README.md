# DomainHunter
[![Build Status](https://img.shields.io/badge/platform-Linux-blue.svg)](https://shields.io/)
![Maintenance](https://img.shields.io/maintenance/yes/2023.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/cybersheepdog/DomainHunter.svg?style=flat-square)](https://github.com/cybersheepdog/DomainHunter/commit/master)
![GitHub](https://img.shields.io/github/license/cybersheepdog/DomainHunter)

Takes a list of domains to monitor and looks for newly registered domain permutations, puts them in an Excel document and then sends out notifications via email with the Excel document attached. 

The first email sends all the currently registered domain permutations along with the Excel document.
Sub-sequent emails are sent when a newly registered domain permutation is detected, and it includes the updated Excel document with the new domain permutation.

The Excel document contains the following columns for each registered domain:
- Permutation Type:
  - Bitsquatting, omissin, substituion, et..
- Date Created
- Last Updated
- Registrant Name
- Organization
- PHash
  - This is a visual hash of the site.  A higher value may indicate it more closely resembles the original site and indicate an adversary setting up infrastructure for phishing attempts.
- Name Server
- IP
- Mail Server
- Registered Email 1
- Registered Email 2 (if it exists)
