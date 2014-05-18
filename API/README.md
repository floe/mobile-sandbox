Mobile-Sandbox (NG) API
=======================

Within this repo you can find the API to interact with the next generation version of the Mobile-Sandbox.

* Upload a suspicious Android app to the Mobile-Sandbox for analysis:
   
        ./submit_sample.py [public submission (0,1)] [email adress] [apk_name] [apk_origin] [apk_file_location]

* Get analysis reports for a given sample:

        ./get_report.py [sample_id] [report_type (static, dynamic)] [destination_dir]

* Get infos to a specific sample:

        ./get_info.py [type (md5,sha256)] [value]

