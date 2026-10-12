package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Alibaba Cloud KMS console operations. Alibaba takes plaintext as text, so
// encrypt refuses binary input rather than changing what it encrypts.

func (p *alibabaProvider) Console() map[string]ConsoleFunc {
	call := func(action string, params func(ConsoleInput) map[string]string, result func(map[string]interface{}) interface{}, cli func(ConsoleInput) string) ConsoleFunc {
		return func(ctx context.Context, c cloudKeyCall, in ConsoleInput) (interface{}, string, error) {
			args := map[string]string{"Action": action}
			if params != nil {
				for k, v := range params(in) {
					args[k] = v
				}
			}
			out, err := p.api(ctx, c, args)
			if err != nil {
				return nil, cli(in), err
			}
			if result == nil {
				return map[string]string{"status": "done"}, cli(in), nil
			}
			return result(out), cli(in), nil
		}
	}
	key := func(in ConsoleInput) map[string]string { return map[string]string{"KeyId": in.Key} }
	field := func(path ...string) func(map[string]interface{}) interface{} {
		return func(m map[string]interface{}) interface{} {
			var v interface{} = m
			for _, k := range path {
				v = asObject(v)[k]
			}
			return v
		}
	}
	simple := func(verb string) func(ConsoleInput) string {
		return func(in ConsoleInput) string { return "aliyun kms " + verb + " --KeyId " + in.Key }
	}
	return map[string]ConsoleFunc{
		"list-keys":     call("ListKeys", func(ConsoleInput) map[string]string { return map[string]string{"PageSize": "100"} }, field("Keys", "Key"), func(ConsoleInput) string { return "aliyun kms ListKeys --PageSize 100" }),
		"describe-key":  call("DescribeKey", key, field("KeyMetadata"), simple("DescribeKey")),
		"list-versions": call("ListKeyVersions", key, field("KeyVersions", "KeyVersion"), simple("ListKeyVersions")),
		"enable-key":    call("EnableKey", key, nil, simple("EnableKey")),
		"disable-key":   call("DisableKey", key, nil, simple("DisableKey")),
		"schedule-key-deletion": call("ScheduleKeyDeletion", func(in ConsoleInput) map[string]string {
			return map[string]string{"KeyId": in.Key, "PendingWindowInDays": strconv.Itoa(in.int("pending_days", 30))}
		}, nil, func(in ConsoleInput) string {
			return fmt.Sprintf("aliyun kms ScheduleKeyDeletion --KeyId %s --PendingWindowInDays %d", in.Key, in.int("pending_days", 30))
		}),
		"cancel-key-deletion": call("CancelKeyDeletion", key, nil, simple("CancelKeyDeletion")),
		"list-aliases": func(ctx context.Context, c cloudKeyCall, in ConsoleInput) (interface{}, string, error) {
			if in.Key != "" {
				return call("ListAliasesByKeyId", key, field("Aliases", "Alias"), simple("ListAliasesByKeyId"))(ctx, c, in)
			}
			return call("ListAliases", nil, field("Aliases", "Alias"), func(ConsoleInput) string { return "aliyun kms ListAliases" })(ctx, c, in)
		},
		"create-alias": call("CreateAlias", func(in ConsoleInput) map[string]string {
			return map[string]string{"KeyId": in.Key, "AliasName": awsAlias(in.Params["alias"])}
		}, nil, func(in ConsoleInput) string {
			return "aliyun kms CreateAlias --KeyId " + in.Key + " --AliasName " + awsAlias(in.Params["alias"])
		}),
		"delete-alias": call("DeleteAlias", func(in ConsoleInput) map[string]string {
			return map[string]string{"AliasName": awsAlias(in.Params["alias"])}
		}, nil, func(in ConsoleInput) string {
			return "aliyun kms DeleteAlias --AliasName " + awsAlias(in.Params["alias"])
		}),
		"list-tags": call("ListResourceTags", key, func(m map[string]interface{}) interface{} {
			out := map[string]string{}
			if list, ok := asObject(m["Tags"])["Tag"].([]interface{}); ok {
				for _, t := range list {
					out[firstString(asObject(t), "TagKey")] = firstString(asObject(t), "TagValue")
				}
			}
			return out
		}, simple("ListResourceTags")),
		"tag-key": call("TagResource", func(in ConsoleInput) map[string]string {
			tags, _ := json.Marshal([]map[string]string{{"TagKey": in.Params["tag_key"], "TagValue": in.Params["tag_value"]}})
			return map[string]string{"KeyId": in.Key, "Tags": string(tags)}
		}, nil, func(in ConsoleInput) string {
			return fmt.Sprintf(`aliyun kms TagResource --KeyId %s --Tags '[{"TagKey":"%s","TagValue":"%s"}]'`, in.Key, in.Params["tag_key"], in.Params["tag_value"])
		}),
		"untag-key": call("UntagResource", func(in ConsoleInput) map[string]string {
			keys, _ := json.Marshal([]string{in.Params["tag_key"]})
			return map[string]string{"KeyId": in.Key, "TagKeys": string(keys)}
		}, nil, func(in ConsoleInput) string {
			return fmt.Sprintf(`aliyun kms UntagResource --KeyId %s --TagKeys '["%s"]'`, in.Key, in.Params["tag_key"])
		}),
		"encrypt": func(ctx context.Context, c cloudKeyCall, in ConsoleInput) (interface{}, string, error) {
			pt := in.bytes("plaintext_b64")
			if !utf8.Valid(pt) {
				return nil, "", refuseBYOK(http.StatusBadRequest, "bad_request", "Alibaba Cloud KMS encrypts text; this plaintext is binary")
			}
			return call("Encrypt", func(in ConsoleInput) map[string]string {
				return map[string]string{"KeyId": in.Key, "Plaintext": string(pt)}
			},
				func(m map[string]interface{}) interface{} {
					return map[string]string{"ciphertext_b64": firstString(m, "CiphertextBlob"), "key_version": firstString(m, "KeyVersionId")}
				}, func(in ConsoleInput) string { return "aliyun kms Encrypt --KeyId " + in.Key + " --Plaintext <text>" })(ctx, c, in)
		},
		"decrypt": func(ctx context.Context, c cloudKeyCall, in ConsoleInput) (interface{}, string, error) {
			out, err := p.api(ctx, c, map[string]string{"Action": "Decrypt", "CiphertextBlob": in.Params["ciphertext_b64"]})
			cli := "aliyun kms Decrypt --CiphertextBlob <base64>"
			if err != nil {
				return nil, cli, err
			}
			return plaintextResult([]byte(firstString(out, "Plaintext"))), cli, nil
		},
	}
}

// Salesforce console operations: the org's tenant secrets, read-only. Shield
// keys are managed in Setup; nothing here changes them.
func (p *salesforceProvider) Console() map[string]ConsoleFunc {
	get := func(ctx context.Context, c cloudKeyCall, path string) (map[string]interface{}, error) {
		token, instance, apiVersion, err := p.resolveConnection(ctx, c.Account, c.Credentials)
		if err != nil {
			return nil, err
		}
		out, err := httpJSONRequest(ctx, p.httpClient, http.MethodGet, instance+"/services/data/"+apiVersion+path, token, nil, nil)
		return asObject(out), err
	}
	return map[string]ConsoleFunc{
		"list-keys": func(ctx context.Context, c cloudKeyCall, _ ConsoleInput) (interface{}, string, error) {
			q := "SELECT Id, Type, Status, Version, Description, CreatedDate FROM TenantSecret ORDER BY CreatedDate DESC"
			out, err := get(ctx, c, "/query?q="+url.QueryEscape(q))
			return okOut(out["records"], err), `sf data query --query "` + q + `"`, err
		},
		"describe-key": func(ctx context.Context, c cloudKeyCall, in ConsoleInput) (interface{}, string, error) {
			if in.Key == "" || strings.HasPrefix(in.Key, "TenantSecret:") { // a BYOK key names the secret type, not a record
				return nil, "", errors.New("name a TenantSecret record id (list keys shows them)")
			}
			out, err := get(ctx, c, "/sobjects/TenantSecret/"+url.PathEscape(in.Key))
			return okOut(out, err), "sf data get record --sobject TenantSecret --record-id " + in.Key, err
		},
	}
}
