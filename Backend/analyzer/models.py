from django.db import models
from django.contrib.auth.models import User
from tastypie.models import create_api_key
#########################################################################################
#create API-Keys for new users
models.signals.post_save.connect(create_api_key, sender=User)
#########################################################################################
class Activities(models.Model):
    id = models.AutoField(primary_key=True)
    activity = models.CharField(max_length=300, db_index=True)
    description = models.CharField(max_length=300)
    class Meta:
        db_table = u'activities'
    def __unicode__(self):
        return "%s" % self.activity
#########################################################################################
class Adnetworks(models.Model):
    id = models.AutoField(primary_key=True, db_index=True)
    network_name = models.CharField(max_length=600)
    smali = models.CharField(max_length=255, db_index=True)
    class Meta:
        db_table = u'adnetworks'
    def __unicode__(self):
        return "%s" % self.network_name
#########################################################################################
class Analyzer(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=150)
    type = models.CharField(max_length=60)
    os = models.CharField(max_length=30)
    tools_integrated = models.CharField(max_length=1500)
    machine_id = models.CharField(max_length=16)
    class Meta:
        db_table = u'analyzer'
    def __unicode__(self):
        return "%s (%s)" % (self.name, self.machine_id)
#########################################################################################
class ApiCalls(models.Model):
    id = models.AutoField(primary_key=True)
    call = models.CharField(max_length=800, db_index=True)
    description = models.CharField(max_length=300)
    class Meta:
        db_table = u'api_calls'
    def __unicode__(self):
        return "%s" % self.call
#########################################################################################
class Av(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_av', db_index=True)
    av_engine = models.CharField(max_length=90, db_index=True)
    result = models.CharField(max_length=150, db_index=True)
    class Meta:
        db_table = u'av'
#########################################################################################
class Certs(models.Model):
    id = models.AutoField(primary_key=True)
    OCN = models.CharField(max_length=300)
    OOU = models.CharField(max_length=300)
    OO = models.CharField(max_length=300)
    OC = models.CharField(max_length=300)
    OL = models.CharField(max_length=300)
    OST = models.CharField(max_length=300)
    ICN = models.CharField(max_length=300)
    IOU = models.CharField(max_length=300)
    IO = models.CharField(max_length=300)
    IC = models.CharField(max_length=300)
    IL = models.CharField(max_length=300)
    IST = models.CharField(max_length=300)
    sn = models.CharField(max_length=300)
    fingerprint_md5 = models.CharField(max_length=384)
    fingerprint_sha256 = models.CharField(max_length=768)
    validFrom = models.DateTimeField()
    validUntil = models.DateTimeField()
    class Meta:
        db_table = u'app_certificates'
    def __unicode__(self):
        return "%s" % self.id
#########################################################################################
class Classifier(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_classifier', db_index=True)
    feature = models.CharField(max_length=300, db_index=True)
    ranking = models.CharField(max_length=300)
    class Meta:
        db_table = u'app_classifier'
#########################################################################################
class ClassifiedApp(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_classified_app', db_index=True)
    score = models.CharField(max_length=300, db_index=True)
    malicious = models.IntegerField()
    class Meta:
        db_table = u'app_classified_app'
#########################################################################################
class Error(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_error', db_index=True)
    msg = models.CharField(max_length=3000)
    class Meta:
        db_table = u'error'
#########################################################################################
class Intents(models.Model):
    id = models.AutoField(primary_key=True)
    intent = models.CharField(max_length=300, db_index=True)
    description = models.CharField(max_length=300)
    class Meta:
        db_table = u'intents'
    def __unicode__(self):
        return "%s" % self.intent
#########################################################################################
class MalwareFamily(models.Model):
    id = models.AutoField(primary_key=True)
    family_name = models.CharField(max_length=300, db_index=True)
    class Meta:
        db_table = u'malware_family'
    def __unicode__(self):
        return "%s" % self.family_name
#########################################################################################
class NeededPermissions(models.Model):
    id = models.AutoField(primary_key=True)
    report_id = models.ForeignKey('Reports', related_name='report_id_2_needed_permissions', db_index=True)
    needed_permission = models.ForeignKey('Permissions', related_name='permission_id_2_needed_permissions', db_index=True)
    class Meta:
        db_table = u'needed_permissions'
#########################################################################################
class Overview(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_overview', db_index=True)
    q01 = models.CharField(max_length=300)
    q02 = models.CharField(max_length=300)
    q03 = models.CharField(max_length=300)
    q04 = models.CharField(max_length=300)
    q05 = models.CharField(max_length=300)
    q06 = models.CharField(max_length=300)
    q07 = models.CharField(max_length=300)
    q08 = models.CharField(max_length=300)
    q09 = models.CharField(max_length=300)
    q10 = models.CharField(max_length=300)
    q11 = models.CharField(max_length=300)
    q12 = models.CharField(max_length=300)
    q13 = models.CharField(max_length=300)
    q14 = models.CharField(max_length=300)
    q15 = models.CharField(max_length=300)
    q16 = models.CharField(max_length=300)
    q17 = models.CharField(max_length=300)
    q18 = models.CharField(max_length=300)
    q19 = models.CharField(max_length=300)
    q20 = models.CharField(max_length=300)
    q21 = models.CharField(max_length=300)
    q22 = models.CharField(max_length=300)
    q23 = models.CharField(max_length=300)
    q24 = models.CharField(max_length=300)
    class Meta:
        db_table = u'overview'
#########################################################################################
class PcapData(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_pcapdata', db_index=True)
    timestamp = models.FloatField()
    conn_type = models.CharField(max_length=50)
    src = models.GenericIPAddressField()
    dst = models.GenericIPAddressField()
    sport = models.IntegerField(default=None, blank=True, null=True)
    dport = models.IntegerField(default=None, blank=True, null=True)
    class Meta:
        db_table = u'pcapdata'
    def __unicode__(self):
        return "%s" % self.id
    def __json__(self):
        data = dict(
                    timestamp = self.timestamp,
                    conn_type = self.conn_type,
                    src = self.src,
                    dst = self.dst,
                    sport = self.sport,
                    dport = self.dport,
                    )
        return data
#########################################################################################
class Permissions(models.Model):
    id = models.AutoField(primary_key=True)
    permission = models.CharField(max_length=300, db_index=True)
    description = models.CharField(max_length=300)
    class Meta:
        db_table = u'permissions'
    def __unicode__(self):
        return "%s" % self.permission
#########################################################################################
class Queue(models.Model):
    id = models.AutoField(primary_key=True)
    priority = models.IntegerField()
    analyzer_type = models.CharField(max_length=30)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_queue', db_index=True)
    status = models.CharField(max_length=60, db_index=True)
    bot = models.CharField(max_length=150)
    android_version = models.CharField(max_length=20)
    min_sdk_version = models.IntegerField()
    public = models.IntegerField()
    class Meta:
        db_table = u'queue'
    def __json__(self):
        data = dict(id = self.id,
                    priority = self.priority,
                    analyzer_type = self.analyzer_type,
                    sample_id = self.sample_id,
                    status = self.status,
                    bot = self.bot,
                    android_version = self.android_version,
                    min_sdk_version = self.min_sdk_version,
                    public = self.public,
                    )
        return data
#########################################################################################
class Reports(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_reports', db_index=True)
    filesystem_position = models.CharField(max_length=1500)
    type_of_report = models.CharField(max_length=60, db_index=True)
    analyzer_id = models.ForeignKey('Analyzer', related_name='analyzer_id_2_reports', db_index=True)
    os = models.CharField(max_length=30)
    password = models.CharField(max_length=15)
    status = models.CharField(max_length=300, db_index=True)
    start_of_analysis = models.DateTimeField()
    end_of_analysis = models.DateTimeField()
    public = models.IntegerField(db_index=True)
    class Meta:
        db_table = u'reports'
    def __unicode__(self):
        return "%s" % self.id
    def __json__(self):
        data = dict(filesystem_position = self.filesystem_position,
                    analyzer_id = self.analyzer_id,
                    )
        return data
#########################################################################################
class Sample(models.Model):
    id = models.AutoField(primary_key=True)
    apk_name = models.CharField(max_length=300)
    package_name = models.CharField(max_length=300)
    md5 = models.CharField(max_length=384, db_index=True)
    sha256 = models.CharField(max_length=768, db_index=True)
    ssdeep = models.CharField(max_length=765)
    filesystem_position = models.CharField(max_length=1500)
    malware_family_id = models.ForeignKey('MalwareFamily', related_name='malware_family_id_2_sample', db_index=True)
    os = models.CharField(max_length=30)
    android_version = models.CharField(max_length=20)
    min_sdk_version = models.IntegerField()
    status = models.CharField(max_length=30, db_index=True)
    class Meta:
        db_table = u'sample'
    def __unicode__(self):
        return "%s" % self.id
    def __json__(self):
        data = dict(apk_name = self.apk_name,
                    package_name = self.package_name,
                    md5 = self.md5,
                    sha256 = self.sha256,
                    ssdeep = self.ssdeep,
                    malware_family = self.malware_family_id,
                    android_build_version = self.android_version,
                    min_sdk_version = self.min_sdk_version,
                    status = self.status,
                    )
        return data
#########################################################################################
class SampleAdnetworks(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_sample_adnetworks', db_index=True)
    adnetwork_id = models.ForeignKey('Adnetworks', related_name='adnetwork_id_2_sample_adnetworks', db_index=True)
    class Meta:
        db_table = u'sample_adnetworks'
#########################################################################################
class SampleOrigin(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_sample_origin', db_index=True)
    origin = models.CharField(max_length=200, db_index=True)
    download_data = models.CharField(max_length=765)
    class Meta:
        db_table = u'sample_origin'
    def __unicode__(self):
        return "%s" % self.origin
#########################################################################################
class ServicesAndReceivers(models.Model):
    id = models.AutoField(primary_key=True)
    service_and_receiver = models.CharField(max_length=300, db_index=True)
    description = models.CharField(max_length=300)
    class Meta:
        db_table = u'services_and_receivers'
    def __unicode__(self):
        return "%s" % self.service_and_receiver
#########################################################################################
class Submission(models.Model):
    id = models.AutoField(primary_key=True)
    uploader_id = models.ForeignKey('User', related_name='user_id_2_submission', db_index=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_submission', db_index=True)
    os = models.CharField(max_length=30)
    status = models.CharField(max_length=30, db_index=True)
    date_of_submission = models.DateTimeField()
    run_name = models.CharField(max_length=300, blank=True)
    public = models.IntegerField()
    class Meta:
        db_table = u'submission'
    def __unicode__(self):
        return "%s" % self.id
#########################################################################################
class Urls(models.Model):
    id = models.AutoField(primary_key=True)
    url = models.CharField(max_length=800, db_index=True)
    class Meta:
        db_table = u'urls'
    def __unicode__(self):
        return "%s" % self.url
#########################################################################################
class UsedActivities(models.Model):
    id = models.AutoField(primary_key=True)
    report_id = models.ForeignKey('Reports', related_name='report_id_2_used_activities', db_index=True)
    used_activity = models.ForeignKey('Activities', related_name='activity_id_2_used_activities', db_index=True)
    class Meta:
        db_table = u'used_activities'
#########################################################################################
class UsedApiCalls(models.Model):
    id = models.AutoField(primary_key=True)
    report_id = models.ForeignKey('Reports', related_name='report_id_2_used_api_calls', db_index=True)
    used_call = models.ForeignKey('ApiCalls', related_name='call_id_2_used_api_calls', db_index=True)
    class Meta:
        db_table = u'used_api_calls'
#########################################################################################
class UsedCerts(models.Model):
    id = models.AutoField(primary_key=True)
    report_id = models.ForeignKey('Reports', related_name='report_id_2_used_certs', db_index=True)
    cert_id = models.ForeignKey('Certs', related_name='certs_id_2_used_certs', db_index=True)
    class Meta:
        db_table = u'used_certificates'
#########################################################################################
class UsedIntents(models.Model):
    id = models.AutoField(primary_key=True)
    report_id = models.ForeignKey('Reports', related_name='report_id_2_used_intents', db_index=True)
    used_intent = models.ForeignKey('Intents', related_name='intent_id_2_used_intents', db_index=True)
    class Meta:
        db_table = u'used_intents'
#########################################################################################
class UsedPermissions(models.Model):
    id = models.AutoField(primary_key=True)
    report_id = models.ForeignKey('Reports', related_name='report_id_2_used_permissions', db_index=True)
    used_permission = models.ForeignKey('Permissions', related_name='permission_id_2_used_permissions', db_index=True)
    class Meta:
        db_table = u'used_permissions'
#########################################################################################
class UsedServicesAndReceivers(models.Model):
    id = models.AutoField(primary_key=True)
    report_id = models.ForeignKey('Reports', related_name='report_id_2_used_services', db_index=True)
    used_service_and_receiver = models.ForeignKey('ServicesAndReceivers', related_name='service_id_2_used_services', db_index=True)
    class Meta:
        db_table = u'used_services_and_receivers'
#########################################################################################
class UsedUrls(models.Model):
    id = models.AutoField(primary_key=True)
    report_id = models.ForeignKey('Reports', related_name='report_id_2_used_urls', db_index=True)
    used_url = models.ForeignKey('Urls', related_name='url_id_2_used_urls', db_index=True)
    class Meta:
        db_table = u'used_urls'
#########################################################################################
class User(models.Model):
    id = models.AutoField(primary_key=True)
    email = models.CharField(max_length=300)
    priority = models.IntegerField()
    name = models.CharField(max_length=150)
    role = models.CharField(max_length=50)
    class Meta:
        db_table = u'user'
    def __unicode__(self):
        return "%s" % self.name
#########################################################################################
class UserIp(models.Model):
    id = models.AutoField(primary_key=True)
    date = models.DateTimeField()
    ip = models.CharField(max_length=48)
    country = models.CharField(max_length=150)
    class Meta:
        db_table = u'user_ip'
#########################################################################################