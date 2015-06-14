from django.conf.urls import patterns, include, url
from tastypie.api import Api
from analyzer.api import SampleResource, QueueResource
from django.views.generic import RedirectView
from django.views.generic import TemplateView

# URL's for the admin (backend)
from django.contrib import admin
admin.autodiscover()

# URL's for the API (backend)
bot_api = Api(api_name='bot')
bot_api.register(SampleResource())
bot_api.register(QueueResource())

# URL's and forwarding for the website (frontend)
urlpatterns = patterns('',
    url(r'^favicon\.ico$', RedirectView.as_view(url='/static/favicon.ico'), name='favicon'),
    url(r'^robots\.txt/$', TemplateView.as_view(template_name='robots.txt', content_type='text/plain')),
    (r'^$', 'analyzer.views.index'),
    (r'^reports/$', 'analyzer.views.reports'),
    (r'^report/$', 'analyzer.views.report'),
    (r'^xml_report_static/$', 'analyzer.views.xml_report_static'),
    (r'^xml_report_dynamic/$', 'analyzer.views.xml_report_dynamic'),
    (r'^search/$', 'analyzer.views.search'),
    (r'^submit/$', 'analyzer.views.submit'),
    (r'^about/$', 'analyzer.views.about'),
    (r'^cert/$', 'analyzer.views.cert'),
    (r'^drebin/$', 'analyzer.views.drebin'),
    (r'^screenshots/$', 'analyzer.views.screenshots'),
    (r'^network/$', 'analyzer.views.network'),
    (r'^av/$', 'analyzer.views.av'),
    (r'^ltrace/$', 'analyzer.views.ltrace'),
    (r'^apk/$', 'analyzer.views.apk'),
    (r'^login/$', 'analyzer.views.loginPage'),
    (r'^logout/$', 'analyzer.views.logoutPage'),
    (r'^loggedin/$', 'analyzer.views.loginVerification'),
    (r'^members/$', 'analyzer.views.memberArea'),
    (r'^member_reports/$', 'analyzer.views.memberReports'),
    (r'^login_error/$', 'analyzer.views.loginError'),
    (r'^saaf_report/$', 'analyzer.views.saaf_report'),
    (r'^overview/$', 'analyzer.views.overview'),
    url(r'^admin/', include(admin.site.urls)),
    (r'^api/', include(bot_api.urls)),
)