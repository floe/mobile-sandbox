from analyzer.models import *
from django.contrib import admin
#########################################################################################
class ActivitiesAdmin(admin.ModelAdmin):
    list_display = ('id', 'activity', 'description',)
#########################################################################################
class AdnetworksAdmin(admin.ModelAdmin):
    list_display = ('id', 'network_name', 'smali',)
#########################################################################################
class AnalyzerAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'type', 'os', 'tools_integrated', 'machine_id',)
#########################################################################################
class ApiCallsAdmin(admin.ModelAdmin):
    list_display = ('id', 'call', 'description',)
#########################################################################################
class AvAdmin(admin.ModelAdmin):
    list_display = ('id', 'sample_id', 'av_engine', 'result',)
    list_filter = ('av_engine', 'result')
#########################################################################################
class ClassifiedAppAdmin(admin.ModelAdmin):
    list_display = ('id', 'sample_id', 'score', 'malicious')
    list_filter = ('malicious',)
#########################################################################################
class ClassifierAdmin(admin.ModelAdmin):
    list_display = ('id', 'sample_id', 'feature', 'ranking')
    list_filter = ('feature', 'ranking')
#########################################################################################
class CertsAdmin(admin.ModelAdmin):
    list_display = ('id', 'OCN', 'OOU', 'OO', 'OC', 'OL', 'OST', 'ICN', 'IOU', 'IO', 'IC', 'IL', 'IST', 'sn', 'fingerprint_md5', 'fingerprint_sha256', 'validFrom', 'validUntil',)
    list_filter = ('OCN', 'OOU', 'OO', 'OC', 'OL', 'OST', 'ICN', 'IOU', 'IO', 'IC', 'IL', 'IST', 'sn',)
#########################################################################################
class ErrorAdmin(admin.ModelAdmin):
    list_display = ('id', 'sample_id', 'msg',)
#########################################################################################
class IntentsAdmin(admin.ModelAdmin):
    list_display = ('id', 'intent', 'description',)
#########################################################################################
class MalwareFamilyAdmin(admin.ModelAdmin):
    list_display = ('id', 'family_name',)
#########################################################################################
class NeededPermissionsAdmin(admin.ModelAdmin):
    list_display = ('id', 'report_id', 'needed_permission',)
    list_filter = ('needed_permission',)
#########################################################################################
class PcapDataAdmin(admin.ModelAdmin):
    list_display = ('id', 'sample_id' , 'timestamp', 'conn_type', 'src', 'dst', 'sport', 'dport',)
#########################################################################################
class PermissionsAdmin(admin.ModelAdmin):
    list_display = ('id', 'permission', 'description',)
#########################################################################################
class OverviewAdmin(admin.ModelAdmin):
    list_display = ('id', 'sample_id', 'q01', 'q02', 'q03', 'q04', 'q05', 'q06', 'q07', 'q08', 'q09', 'q10', 'q11', 'q12', 'q13', 'q14', 'q15', 'q16', 'q17', 'q18', 'q19', 'q20', 'q21', 'q22', 'q23', 'q24',)
#########################################################################################
class QueueAdmin(admin.ModelAdmin):
    list_display = ('id', 'priority', 'analyzer_type', 'sample_id', 'status', 'bot', 'android_version', 'min_sdk_version', 'public', )
    list_filter = ('priority', 'analyzer_type', 'status', 'bot', 'android_version', 'min_sdk_version',)
#########################################################################################
class ReportsAdmin(admin.ModelAdmin):
    list_display = ('id', 'sample_id', 'filesystem_position', 'type_of_report', 'analyzer_id', 'os', 'password', 'status', 'start_of_analysis', 'end_of_analysis', 'public',)
    list_filter = ('type_of_report', 'analyzer_id', 'status', 'public',)
#########################################################################################
class SampleAdmin(admin.ModelAdmin):
    list_display = ('id', 'apk_name', 'package_name', 'md5', 'sha256', 'ssdeep', 'filesystem_position', 'malware_family_id', 'os', 'android_version', 'min_sdk_version', 'status',)
    list_filter = ('malware_family_id', 'android_version', 'min_sdk_version',)
#########################################################################################
class SampleAdnetworksAdmin(admin.ModelAdmin):
    list_display = ('id', 'sample_id', 'adnetwork_id', )
#########################################################################################
class SampleOriginAdmin(admin.ModelAdmin):
    list_display = ('id', 'sample_id', 'origin', 'download_data',)
    list_filter = ('origin',)
#########################################################################################
class ServicesAndReceiversAdmin(admin.ModelAdmin):
    list_display = ('id', 'service_and_receiver', 'description',)
#########################################################################################
class SubmissionAdmin(admin.ModelAdmin):
    list_display = ('id', 'uploader_id', 'sample_id', 'os', 'status', 'date_of_submission', 'run_name', 'public',)
    list_filter = ('uploader_id', 'public',)
#########################################################################################
class UrlsAdmin(admin.ModelAdmin):
    list_display = ('id', 'url',)
#########################################################################################
class UsedActivitiesAdmin(admin.ModelAdmin):
    list_display = ('id', 'report_id', 'used_activity',)
#########################################################################################
class UsedApiCallsAdmin(admin.ModelAdmin):
    list_display = ('id', 'report_id', 'used_call',)
#########################################################################################
class UsedCertsAdmin(admin.ModelAdmin):
    list_display = ('id', 'report_id', 'cert_id',)
#########################################################################################
class UsedIntentsAdmin(admin.ModelAdmin):
    list_display = ('id', 'report_id', 'used_intent',)
#########################################################################################
class UsedPermissionsAdmin(admin.ModelAdmin):
    list_display = ('id', 'report_id', 'used_permission',)
#########################################################################################
class UsedServicesAndReceiversAdmin(admin.ModelAdmin):
    list_display = ('id', 'report_id', 'used_service_and_receiver',)
#########################################################################################
class UsedUrlsAdmin(admin.ModelAdmin):
    list_display = ('id', 'report_id', 'used_url',)
#########################################################################################
class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'priority', 'name', 'role',)
    list_filter = ('priority', 'role')
#########################################################################################
class UserIpAdmin(admin.ModelAdmin):
    list_display = ('id', 'date', 'ip', 'country',)
    list_filter = ('country',)
#########################################################################################
admin.site.register(Activities, ActivitiesAdmin)
admin.site.register(Adnetworks, AdnetworksAdmin)
admin.site.register(Analyzer, AnalyzerAdmin)
admin.site.register(ApiCalls, ApiCallsAdmin)
admin.site.register(Av, AvAdmin)
admin.site.register(Classifier, ClassifierAdmin)
admin.site.register(ClassifiedApp, ClassifiedAppAdmin)
admin.site.register(Certs, CertsAdmin)
admin.site.register(Error, ErrorAdmin)
admin.site.register(Intents, IntentsAdmin)
admin.site.register(MalwareFamily, MalwareFamilyAdmin)
admin.site.register(NeededPermissions, NeededPermissionsAdmin)
admin.site.register(Overview, OverviewAdmin)
admin.site.register(PcapData, PcapDataAdmin)
admin.site.register(Permissions, PermissionsAdmin)
admin.site.register(Queue, QueueAdmin)
admin.site.register(Reports, ReportsAdmin)
admin.site.register(Sample, SampleAdmin)
admin.site.register(SampleAdnetworks, SampleAdnetworksAdmin)
admin.site.register(SampleOrigin, SampleOriginAdmin)
admin.site.register(ServicesAndReceivers, ServicesAndReceiversAdmin)
admin.site.register(Submission, SubmissionAdmin)
admin.site.register(Urls, UrlsAdmin)
admin.site.register(UsedActivities, UsedActivitiesAdmin)
admin.site.register(UsedApiCalls, UsedApiCallsAdmin)
admin.site.register(UsedCerts, UsedCertsAdmin)
admin.site.register(UsedIntents, UsedIntentsAdmin)
admin.site.register(UsedPermissions, UsedPermissionsAdmin)
admin.site.register(UsedServicesAndReceivers, UsedServicesAndReceiversAdmin)
admin.site.register(UsedUrls, UsedUrlsAdmin)
admin.site.register(User, UserAdmin)
admin.site.register(UserIp, UserIpAdmin)
#########################################################################################