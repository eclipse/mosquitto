{{/* vim: set filetype=mustache: */}}
{{/*
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}

{{- define "mosquitto.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mosquitto.name" -}}
{{- default .Chart.Name .Values.mosquitto.nameOverride | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mosquitto.fullname" -}}
{{- $name := default .Chart.Name .Values.mosquitto.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" $name .Release.Name | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "mosquitto.labels.standard" -}}
app.kubernetes.io/name: {{ include "mosquitto.name" . }}
helm.sh/chart: {{ include "mosquitto.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ required ".Values.mosquitto.imageTag is required!" .Values.mosquitto.imageTag | quote }}
{{- end -}}

{{- define "mosquitto.labels.matchLabels" -}}
app.kubernetes.io/name: {{ include "mosquitto.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "mosquitto.capabilities.kubeVersion" -}}
{{- .Capabilities.KubeVersion.Version -}}
{{- end -}}

{{- define "mosquitto.capabilities.ingress.apiVersion" -}}
{{- if semverCompare "<1.14-0" (include "mosquitto.capabilities.kubeVersion" .) -}}
{{- print "extensions/v1beta1" -}}
{{- else if semverCompare "<1.19-0" (include "mosquitto.capabilities.kubeVersion" .) -}}
{{- print "networking.k8s.io/v1beta1" -}}
{{- else -}}
{{- print "networking.k8s.io/v1" -}}
{{- end -}}
{{- end -}}

{{- define "mosquitto.capabilities.policy.apiVersion" -}}
{{- if semverCompare "<1.21-0" (include "mosquitto.capabilities.kubeVersion" .) -}}
{{- print "policy/v1beta1" -}}
{{- else -}}
{{- print "policy/v1" -}}
{{- end -}}
{{- end -}}

{{- define "mosquitto.capabilities.rbac.apiVersion" -}}
{{- if semverCompare "<1.17-0" (include "mosquitto.capabilities.kubeVersion" .) -}}
{{- print "rbac.authorization.k8s.io/v1beta1" -}}
{{- else -}}
{{- print "rbac.authorization.k8s.io/v1" -}}
{{- end -}}
{{- end -}}

{{- define "mosquitto.capabilities.statefulset.apiVersion" -}}
{{- if semverCompare "<1.14-0" (include "mosquitto.capabilities.kubeVersion" .) -}}
{{- print "apps/v1beta1" -}}
{{- else -}}
{{- print "apps/v1" -}}
{{- end -}}
{{- end -}}

{{- define "mosquitto.ingress.backend" -}}
{{- $apiVersion := (include "mosquitto.capabilities.ingress.apiVersion" .context) -}}
{{- if or (eq $apiVersion "extensions/v1beta1") (eq $apiVersion "networking.k8s.io/v1beta1") -}}
serviceName: {{ .serviceName }}
servicePort: {{ .servicePort }}
{{- else -}}
service:
  name: {{ .serviceName }}
  port:
    {{- if typeIs "string" .servicePort }}
    name: {{ .servicePort }}
    {{- else if or (typeIs "int" .servicePort) (typeIs "float64" .servicePort) }}
    number: {{ .servicePort | int }}
    {{- end }}
{{- end -}}
{{- end -}}

{{- define "mosquitto.ingress.supportsPathType" -}}
{{- if semverCompare "<1.18-0" (include "mosquitto.capabilities.kubeVersion" .) -}}
{{- print "false" -}}
{{- else -}}
{{- print "true" -}}
{{- end -}}
{{- end -}}
