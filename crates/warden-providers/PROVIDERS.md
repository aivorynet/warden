# Providers: confirmed capability matrix

Rule (PLAN.md): a cell that is not confirmed in official docs returns `ProviderUnsupported`
and `capabilities()` reports false. Checked 2026-11-24. All listed cells are confirmed.

| Provider | verify | rotate_self | create_derived | revoke | Docs |
|---|---|---|---|---|---|
| GitLab | `GET /personal_access_tokens/self` | `POST /personal_access_tokens/self/rotate`, `expires_at` always sent (AtomicSwap) | `POST /projects/:id/access_tokens` | `DELETE /projects/:id/access_tokens/:token_id` (204) | https://docs.gitlab.com/api/personal_access_tokens/ , https://docs.gitlab.com/api/project_access_tokens/ |
| AWS IAM (Overlap) | `sts:GetCallerIdentity` + `iam:ListAccessKeys` | `CreateAccessKey` for own user, max 2 keys, `TagUser` key=access key id value=`aivw_...` | `CreateAccessKey` for config `user_name` + tag | `DeleteAccessKey` | https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html , API_DeleteAccessKey.html , API_ListAccessKeys.html , API_TagUser.html , https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html |
| Cloudflare | `GET /user/tokens/verify` | `PUT /user/tokens/{id}/value` then verify (AtomicSwap) | `POST /user/tokens` (name, policies, expires_on) | `DELETE /user/tokens/{id}` | https://developers.cloudflare.com/api/resources/user/subresources/tokens/ (+ `/methods/create/`, `/subresources/value/methods/update/`) |
| OpenAI (Overlap) | `GET /organization/admin_api_keys?limit=1` (200 = valid admin key) | `POST /organization/admin_api_keys` (create new; engine revokes old) | `POST /organization/projects/{id}/service_accounts` (returns `api_key.value`) | `DELETE .../service_accounts/{id}` or `DELETE /organization/admin_api_keys/{id}` | https://developers.openai.com/api/reference/resources/organization/subresources/projects/subresources/service_accounts , https://developers.openai.com/api/reference/resources/organization/subresources/admin_api_keys |
| Command | `verify` script | `rotate` script | `create` script | `revoke` script | user scripts; capability true only if the script is configured |
| Manual | stored expiry | unsupported | unsupported | unsupported | none |

## Notes and gaps

- Cloudflare roll: docs show no request body. The client sends `{}`. Base URL
  `https://api.cloudflare.com/client/v4` is not on the fetched reference page.
- GitLab create: docs state no success status code. The client accepts any 2xx.
- OpenAI verify: no dedicated verify endpoint exists. The list call stands in. `admin_key_id`
  in config fills `provider_token_id`.
- OpenAI service account ids are `<project_id>/<service_account_id>`.
- AWS STS uses API version 2011-06-15, IAM uses 2010-05-08.
- Retryable errors have the prefix `retryable:` in `WardenError::Provider` (5xx, timeout).
