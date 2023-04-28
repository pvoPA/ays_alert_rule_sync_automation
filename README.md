# ays_alert_rule_sync_automation

This repository includes the scripts for syncing alert rules in Prisma and Dockerfiles for running the scripts in a docker container.

## Requirements

* Python 3.10
* Docker

## Docker

* Within the `app/` directory, run the following commands...
  * `docker compose build`
  * `docker compose up`

* To debug and interact in the container,
  * `docker run -it ays_alert_rule_sync:latest /bin/bash`

## Testing

* Rename `.env.template` to `.env`
* Configure `CSPM_ENDPOINT` to point to your tenant.
* Configure your access/secret key pair in `.env`, you can generate the key pair in PRISMA console.

To run the scripts in a venv run the following commands,

* `python -m venv .venv`
* `source .venv/bin/activate`
* `pip install -r app/requirements.txt`
* `python app/sync_alert_rules.py`

You can exit the virtual env by running the following command,

* `deactivate`

### API Calls made by sync_alert_rules.py

1. [POST - Token](https://prisma.pan.dev/api/cloud/cspm/login#operation/app-login)
2. [POST - RQL Query](https://prisma.pan.dev/api/cloud/cspm/search#operation/search-config)
3. [GET - Alert Rules](https://pan.dev/prisma-cloud/api/cspm/get-alert-rules-v-2/)
4. [POST - Create Alert Rule](https://pan.dev/prisma-cloud/api/cspm/get-alert-rules-v-2/)
5. [GET - CSPM Policies](https://pan.dev/prisma-cloud/api/cspm/get-policies-v-2/)
5. [GET - Account Groups](https://pan.dev/prisma-cloud/api/cspm/get-account-groups/)
5. [DELETE - Delete Alert Rule](https://pan.dev/prisma-cloud/api/cspm/delete-alert-rule/)
