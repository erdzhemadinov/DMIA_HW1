from flask import Flask
from flask import Flask, render_template, flash, request
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField
import re
import lightgbm as lgb
import os
import string
import pandas as pd
import numpy as np
from collections import Counter
import joblib
from sklearn.metrics import mean_squared_log_error


app = Flask(__name__)
DEBUG = True
app.config.from_object(__name__)
app.config['SECRET_KEY'] = '7d441f27d441f27567d441f2b6176a'


class FeaturesExtract:
    def __init__(self):

        self.data_dir = './data/'
        self.adding_data_dir = "./add/"
        self.full_pass_date = "./add/passwords/"

        self.freq = dict(pd.read_csv(os.path.join(self.adding_data_dir, "freq_eng_words.csv")).values)

        self.regex = re.compile(
            r'^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]))\1|(?:(?:29|30)(\/|-|\.)(?:0?[13-9]|1[0-2])\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$'
            r'|^(?:29(\/|-|\.)0?2\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1'
            r'-9]|1\d|2[0-8])(\/|-|\.)(?:(?:0?[1-9])|(?:1[0-2]))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$')
        self.passwords = self.get_freq()
        self.freq_pass = self.get_top_1000_passes()

    def get_freq(self):
        """
        Load leaked database
        """
        df = pd.read_csv(os.path.join(self.adding_data_dir, "EyeEM dehashed 272k lines.txt"), sep=":", header=None)
        z = df[1]
        return dict(Counter(z))

    def get_top_1000_passes(self):
        """
        Get most used passwords
        """
        with open(os.path.join(self.adding_data_dir, "top10000.txt"), 'r') as f:
            passes = {line.strip(): 1 for line in f}
        return passes

    # def get_all_password_data(self):
    #     for index, i in enumerate(os.listdir(self.full_pass_date)):
    #
    #         if index == 0:
    #             all_passwords = pd.read_csv(os.path.join(self.full_pass_date, i))
    #
    #         else:
    #             all_passwords = all_passwords.append(pd.read_csv(os.path.join(self.full_pass_date, i)))
    #
    #     return all_passwords.drop("hash", axis=1)

    # def get_sha_word_dicts(self):
    #     sha_word_arr = {hashlib.sha1(str.encode(i)).hexdigest().upper(): i for i in
    #                     list(set(train.Password.values).union(set(test.Password.values)))}
    #     word_sha_arr = {i: hashlib.sha1(str.encode(i)).hexdigest().upper() for i in
    #                     list(set(train.Password.values).union(set(test.Password.values)))}
    #
    #     return sha_word_arr, word_sha_arr
    #
    # def read_in_chunks(self, file_object, chunk_size=1024):
    #     """
    #     Lazy function (generator) to read a file piece by piece.
    #     Default chunk size: 1k.
    #     """
    #
    #     cnt = 0
    #     while True:
    #         cnt += 1
    #
    #         data = file_object.read(chunk_size)
    #         for i in data.split("\n"):
    #
    #             try:
    #                 sha, freq = i.split(":")
    #
    #                 if sha in self.hash_to_word.keys():
    #                     self.sha_arr_existed[sha] = freq
    #
    #                     if len(self.sha_arr_existed.keys()) % 200000 == 0:
    #                         print("{0} values in dict".format(len(self.sha_arr_existed.keys())))
    #             except Exception as e:
    #                 # print(i, e)
    #                 pass
    #
    #         if not data:
    #             break
    #         yield data
    #
    # def get_sha_freq_all_data(self):
    #     print("Load Freq dataset")
    #     with open(os.path.join(self.adding_data_dir, 'pwned-passwords-sha1-ordered-by-count-v7.txt')) as f:
    #         for piece in self.read_in_chunks(f, 1024 * 1024 * 10):
    #             pass
    #     print("Done")
    #
    # def get_rock_dataset(self):
    #     print("Load Rock dataset")
    #     rock = pd.read_csv(os.path.join(self.adding_data_dir, "rockyou-withcount.txt"), header=None, sep="\t",
    #                        engine='python', encoding='latin1')
    #     rock.columns = ['read']
    #
    #     rock['read_freq'], rock['read_word'] = zip(*rock['read'].apply(lambda x: re.sub(' +', ' ', x)[1:].split(" ")))
    #
    #     rock_pass_freq = dict(rock[['read_word', 'read_freq']].values)
    #     print("Done")
    #     return rock_pass_freq
    #
    # def get_10kk_pass_freq(self):
    #     passwords_10kk = pd.read_csv(os.path.join(self.adding_data_dir, "10-million-passwords.txt"), header=None,
    #                                  sep="\t", engine='python', encoding='latin1')
    #
    #     z = passwords_10kk[0]
    #
    #     return dict(Counter(z))

    def get_words_freq(self, x):

        if x.lower() in self.freq.keys():
            return self.freq[x.lower()]
        else:
            return 0

    def get_words_freq_without_digits(self, x):

        no_digit = ''.join([i for i in x if not i.isdigit()])

        if no_digit.lower() in self.freq.keys():

            return self.freq[no_digit.lower()]
        else:
            return 0


    def extract_birthday(self, x):

        """
        Extract ans check if 8 digit password is a birthday.
        """

        if x.isdigit() and len(x) == 8:
            _temp_row = x[0:2] + "." + x[2:4] + "." + x[4:8]
            if self.regex.fullmatch(_temp_row) is None:
                return 0
            else:

                return 1
        else:
            return 0

    def get_pass_freq(self, x):

        if x in self.passwords.keys():
            return self.passwords[x]
        else:
            return 0

    def is_from_top(self, x):
        if x in self.freq_pass.keys():
            return 1
        else:
            return 0
    #
    # def was_pwnedpasswords(self, x):
    #
    #     freq = pwnedpasswords.check(x)
    #
    #     return x

    # def all_pass_freq(self, x):
    #     if x in self.pass_600k_freq.keys():
    #         return int(self.pass_600k_freq[x])
    #     else:
    #         return 0
    #
    # def get_pass_from_rock(self, x):
    #
    #     if x in self.rock_dataset.keys():
    #         return int(self.rock_dataset[x])
    #     else:
    #         return 0
    #
    # def get_pass_freq_500mln(self, x):
    #
    #     if self.word_to_hash[x] in self.sha_arr_existed.keys():
    #         return int(self.sha_arr_existed[self.word_to_hash[x]])
    #     else:
    #         return 0
    #


@app.route('/', methods=['GET','POST'])
def index():
    def predict(x):

        features = []
        # length
        features.append(len(x))
        # punkt
        features.append(len("".join(_ for _ in x if _ in string.punctuation)))
        # title letters count
        features.append(len([wrd for wrd in x if wrd.istitle()]))
        # lower letter count
        features.append(len([wrd for wrd in x if wrd.islower()]))
        # digit count
        features.append(len([wrd for wrd in x if wrd.isdigit()]))
        # punkt ratio
        features.append(len("".join(_ for _ in x if _ in string.punctuation)) / len(x))
        # title ratio
        features.append(len([wrd for wrd in x if wrd.istitle()]) / len(x))
        # lower ratio
        features.append(len([wrd for wrd in x if wrd.islower()]) / len(x))
        # digit ratio
        features.append(len([wrd for wrd in x if wrd.isdigit()]) / len(x))

        # english word freq
        features.append(fe.get_words_freq(x))

        # words freq without digit (ex admin121 --> admin)
        features.append(fe.get_words_freq_without_digits(x))

        # is birthday
        features.append(fe.extract_birthday(x))
        # password freq
        features.append(fe.get_pass_freq(x))
        # top passwords
        features.append(fe.is_from_top(x))

        return features, np.exp(model.predict([features])[0] - 1)

    fe = FeaturesExtract()
    model = joblib.load('lgb.pkl')

    errors = ''
    if request.method == "GET":
        return render_template("index.html", errors=errors)
    else:

        password = request.form['password'].strip()
        if not password:
            errors = "Please enter all the fields."
        else:
            features, counter = predict(password)

        if not errors:
            data = {
                'password' : password,
                'count': counter,
                'features': features
                    }
            return render_template("repeat.html", data=data)

        data = {
            'name': password,
        }

        return render_template("index.html", errors=errors, data=data)


if __name__ == '__main__':
    app.run()
