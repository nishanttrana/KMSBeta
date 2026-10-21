{{/* Vecta KMS chart helpers (docs/KUBERNETES.md). */}}

{{- define "vecta.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "vecta.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "vecta.selector" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "vecta.tag" -}}
{{- .Values.image.tag | default .Chart.AppVersion -}}
{{- end -}}

{{- define "vecta.secretName" -}}
{{- .Values.existingSecret | default (printf "%s-secrets" (include "vecta.fullname" .)) -}}
{{- end -}}

{{/* The enabled Compose profiles, as infra/scripts/parse-deployment.sh
     computes them, as a JSON object {"profiles": [...]}. */}}
{{- define "vecta.profiles" -}}
{{- $p := list -}}
{{- range $k, $v := .Values.deployment.features -}}
{{- if $v }}{{- $p = append $p $k -}}{{- end -}}
{{- end -}}
{{- $mode := lower (toString .Values.deployment.hsm_mode) -}}
{{- if not (has $mode (list "software" "none" "hardware" "auto")) -}}
{{- fail (printf "deployment.hsm_mode %q: use software, hardware or auto" $mode) -}}
{{- end -}}
{{- if has $mode (list "hardware" "auto") }}{{- $p = append $p "hsm_hardware" -}}{{- end -}}
{{- $p = concat $p (list "event_streaming" "service_discovery" "distributed_cache") -}}
{{- dict "profiles" $p | toJson -}}
{{- end -}}

{{/* Environment set from values rather than Compose's defaults, applied to
     the containers that have the variable. */}}
{{- define "vecta.envOverrides" -}}
{{- $profiles := (include "vecta.profiles" . | fromJson).profiles -}}
{{- $mode := lower (toString .Values.deployment.hsm_mode) -}}
{{- if not (has (toString .Values.fipsMode) (list "on" "only" "off")) -}}
{{- fail (printf "fipsMode %q: use on, only or off" (toString .Values.fipsMode)) -}}
{{- end -}}
{{- $o := dict "BUILD_VERSION" (include "vecta.tag" .) "VECTA_FIPS_MODE" (toString .Values.fipsMode) "GODEBUG" (printf "fips140=%s" .Values.fipsMode) "HSM_MODE" $mode "VECTA_DEPLOYED_PROFILES" (join "," $profiles) -}}
{{- if has $mode (list "hardware" "auto") }}{{- $_ := set $o "HSM_ENDPOINT" "hsm-connector:18430" -}}{{- end -}}
{{- with .Values.deployment.cert_security -}}
{{- if .cert_storage_mode }}{{- $_ := set $o "CERTS_STORAGE_MODE" .cert_storage_mode -}}{{- end -}}
{{- if .root_key_mode }}{{- $_ := set $o "CERTS_ROOT_KEY_MODE" .root_key_mode -}}{{- end -}}
{{- end -}}
{{- $o | toJson -}}
{{- end -}}
