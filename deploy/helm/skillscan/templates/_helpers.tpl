{{/* Common labels, following the standard Helm chart label convention. */}}
{{- define "skillscan.labels" -}}
app.kubernetes.io/name: skillscan
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Call as: include "skillscan.image" (dict "root" $ "repo" .Values.image.monolithRepository)
     `$`/`.` inside an included template are rebound to whatever is passed in,
     so the caller's root context must be threaded through explicitly.

     An empty image.registry emits NO prefix at all (not a leading "/"), which
     is what the air-gapped default needs: side-loaded images are named
     `skillscan/monolith:<tag>` with no registry component, and
     `/skillscan/monolith:<tag>` is not the same reference - it is an invalid
     one. See values.yaml's image.registry comment. */}}
{{- define "skillscan.image" -}}
{{ with .root.Values.image.registry }}{{ . }}/{{ end }}{{ .repo }}:{{ .root.Values.image.tag }}
{{- end -}}
