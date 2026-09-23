{{- define "mcp-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mcp-gateway.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "mcp-gateway.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}