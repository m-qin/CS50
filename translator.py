import os
import requests
import json
from cs50 import SQL

vocab = 'numbers'

api_key = os.environ.get("API_KEY")
db = SQL("sqlite:///final_project.db")
words = db.execute("SELECT word from :vocab", vocab=vocab)

for word in words:
    url = f"https://translate.yandex.net/api/v1.5/tr.json/translate?key={api_key}&text={word['word']}&lang=sw"
    req = requests.get(url)
    defn = json.loads(req.text)['text'][0]
    db.execute("UPDATE :vocab SET Swahili = :defn WHERE word = :word", vocab=vocab, defn=defn, word = word['word'])


# # for more information on how to install requests
# # http://docs.python-requests.org/en/master/user/install/#install
# import  requests
# import json
# # TODO: replace with your own app_id and app_key
# app_id = ''
# app_key = ''
# language = 'zh'
# word_id = '你好'
# url = 'https://od-api.oxforddictionaries.com:443/api/v2/entries/'  + language + '/'  + word_id.lower()
# #url Normalized frequency
# urlFR = 'https://od-api.oxforddictionaries.com:443/api/v2/stats/frequency/word/'  + language + '/?corpus=nmc&lemma=' + word_id.lower()
# r = requests.get(url, headers = {'app_id' : app_id, 'app_key' : app_key})
# print("code {}\n".format(r.status_code))
# print("text \n" + r.text)
# print("json \n" + json.dumps(r.json()))

# https://translate.yandex.net/api/v1.5/tr.json/translate
#  ? key=<>
#  & text=<bus>
#  & lang=<en-zh>
#  & [format=<text format>]
#  & [options=<translation options>]
#  & [callback=<name of the callback function>]

# from yandex import Translater

# tr = Translater()
# tr.set_key('')
# tr.set_text("Hello World")
# tr.set_from_lang('en')
# tr.set_to_lang('zh')

# result = tr.translate()

# print(result)