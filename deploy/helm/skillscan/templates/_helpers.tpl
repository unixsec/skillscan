{{/* Common labels, following the standard Helm chart label convention. */}}
{{- define "skillscan.labels" -}}
app.kubernetes.io/name: skillscan
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Call as: include "skillscan.image" (dict "root" $ "repo" .Values.image.monolithRepository)
     `$`/`.` inside an included template are rebound to whatever is passed in,
     so the caller's root context must be threaded through explicitly. */}}
{{- define "skillscan.image" -}}
{{ .root.Values.image.registry }}/{{ .repo }}:{{ .root.Values.image.tag }}
{{- end -}}
