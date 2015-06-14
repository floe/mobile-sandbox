from django import template

register = template.Library()

@register.filter
def get_result(dictionary, key):
    return dictionary.get(key)

@register.filter
def get_report_result(dictionary, key):
    reportObject = dictionary.get(key)
    try:
        analyzerName = reportObject[0].analyzer_id.name
    except:
        analyzerName = None
    return analyzerName