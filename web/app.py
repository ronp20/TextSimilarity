import enum
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy


app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
# client = MongoClient("127.0.0.1:27017")

db = client.SimilarityDB
users = db["Users"]


class HttpStatus(enum.Enum):
    """
    Http status
    """
    OK = 200,
    INVALID_USER = 301,
    INVALID_PW = 302,
    OUT_OF_TOKENS = 303,
    INVALID_JSON = 304,
    INVALID_ADMIN_PW = 304

class JsonSyntax:
    """
    The json syntax as expected
    """
    static_user_name = "username"
    static_pw = "password"
    static_text1 = "text1"
    static_text2 = "text2"
    static_tokens = "tokens"
    static_admin_user = "admin_user"

    @staticmethod
    def message(message: str, http_return_code: HttpStatus):
        """
        Create json message
        :param message:
        :param http_return_code:
        :return: dict
        """
        return {
            "Message": message,
            "Status Code": http_return_code.value
        }

class Register(Resource):
    """
    Register resource.
    Register the user to the mongodb
    """
    def __is_valid(self, posted_data: dict):
        """
        helper function that checks for register validation
        :param posted_data: dict of posted data
        :return: http status
        """
        if JsonSyntax.static_user_name in posted_data and JsonSyntax.static_pw in posted_data:
            return HttpStatus.OK

        return HttpStatus.INVALID_JSON

    @staticmethod
    def log_in(user_name: str, password: str):
        """
        log in the user to the system if user and password are correct
        :param user_name:
        :param password:
        :return: list of http status and user data if necessary
        """
        user = users.find_one({JsonSyntax.static_user_name: user_name})
        if user is None:
            return [HttpStatus.INVALID_USER]

        hashad_pw = user[JsonSyntax.static_pw]
        if bcrypt.hashpw(password.encode('utf8'), hashad_pw) != hashad_pw:
            return [HttpStatus.INVALID_PW]

        return [HttpStatus.OK, user]

    def post(self):
        """
        post request
        expected to get
        {
            username:
            password
        }
        register user
        :return: jsonify message
        """
        posted_data = request.get_json()
        if self.__is_valid(posted_data) == HttpStatus.INVALID_JSON:
            return jsonify(JsonSyntax.message("Invalid input", HttpStatus.INVALID_JSON))

        user_name = posted_data[JsonSyntax.static_user_name]
        if users.find_one({JsonSyntax.static_user_name: user_name}) is not None:
            return jsonify(JsonSyntax.message("User Exists", HttpStatus.INVALID_USER))

        password = posted_data[JsonSyntax.static_pw]
        hash_password = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        default_token = 6
        users.insert({
            JsonSyntax.static_user_name: user_name,
            JsonSyntax.static_pw: hash_password,
            JsonSyntax.static_tokens: default_token
        })

        return jsonify(JsonSyntax.message(user_name + " was register!", HttpStatus.OK))


class Detect(Resource):
    """
    Class detect is checking for similarity between two strings using spacy library models
    """
    def __is_valid(self, posted_data: dict):
        """
        helper function that checks for register validation
        :param posted_data: dict of posted data
        :return: http status
        """
        if JsonSyntax.static_pw in posted_data and JsonSyntax.static_user_name in posted_data and JsonSyntax.static_text1 in posted_data and JsonSyntax.static_text2 in posted_data:
            return HttpStatus.OK

        return HttpStatus.INVALID_JSON

    def post(self):
        """
        post request
        expected to get
        {
            username:
            password:
            text1:
            text2:
        }
        Check similarty between text1 and text 2
        :return: json message
        """
        posted_data = request.get_json()
        http_status = self.__is_valid(posted_data)
        if http_status == HttpStatus.INVALID_JSON:
            return jsonify(JsonSyntax.message("Invalid input", HttpStatus.INVALID_JSON))

        user_name = posted_data[JsonSyntax.static_user_name]
        hashad_pw = posted_data[JsonSyntax.static_pw]
        user_data = Register.log_in(user_name, hashad_pw)
        if user_data[0] != HttpStatus.OK:
            return jsonify(JsonSyntax.message("Wrong Password", HttpStatus.INVALID_PW)) if user_data[0] == HttpStatus.INVALID_PW else jsonify(JsonSyntax.message("User not exists", HttpStatus.INVALID_USER))

        #check amount of tokens
        current_tokens = user_data[1][str(JsonSyntax.static_tokens)]
        if current_tokens == 0:
            return jsonify(JsonSyntax.message("Out of tokens", HttpStatus.OUT_OF_TOKENS))

        text1 = posted_data[JsonSyntax.static_text1]
        text2 = posted_data[JsonSyntax.static_text2]

        #load spacy model
        nlp = spacy.load("en_core_web_sm")

        text1 = nlp(text1)
        text2 = nlp(text2)

        #Ratio is a number between 0 and 1. The closer to 1 the more similer the texts are
        ratio = text1.similarity(text2)

        users.update({
            JsonSyntax.static_user_name: user_name
        }, {
                "$set": {
                    JsonSyntax.static_tokens: current_tokens - 1
                }
        })

        message = "The similarity is: {}".format(ratio)
        return jsonify(JsonSyntax.message(message, HttpStatus.OK))


class AddTokens(Resource):
    def __is_valid(self, posted_data: dict):
        """
        helper function that checks for register validation
        :param posted_data: dict of posted data
        :return: http status
        """

        if JsonSyntax.static_pw in posted_data and JsonSyntax.static_user_name in posted_data and JsonSyntax.static_admin_user in posted_data and JsonSyntax.static_tokens in posted_data:
            return HttpStatus.OK

        return HttpStatus.INVALID_JSON

    def post(self):
        """

        :return:
        """
        posted_data = request.get_json()
        if self.__is_valid(posted_data) == HttpStatus.INVALID_JSON:
            return jsonify(JsonSyntax.message("Invalid input", HttpStatus.INVALID_JSON))

        admin_user = posted_data[str(JsonSyntax.static_admin_user)]
        hashad_pw = posted_data[str(JsonSyntax.static_pw)]
        admin_data = Register.log_in(admin_user, hashad_pw)
        if admin_data[0] != HttpStatus.OK:
            return jsonify(JsonSyntax.message("Wrong Password", HttpStatus.INVALID_PW)) if admin_data[0] == HttpStatus.INVALID_PW else jsonify(JsonSyntax.message("User not exists", HttpStatus.INVALID_USER))

        user_name = posted_data[JsonSyntax.static_user_name]
        user = users.find_one({JsonSyntax.static_user_name: user_name})
        if user is None:
            message = "{} is not exists".format(user_name)
            return jsonify(JsonSyntax.message(message, HttpStatus.INVALID_USER))

        user_tokens = user[str(JsonSyntax.static_tokens)]
        user_tokens += posted_data[JsonSyntax.static_tokens]
        users.update({
            JsonSyntax.static_user_name: user_name
        }, {
                "$set": {
                    JsonSyntax.static_tokens: user_tokens
                }
        })

        message = "{} has now {} tokens".format(user_name, user_tokens)
        return jsonify(JsonSyntax.message(message, HttpStatus.OK))


api.add_resource(Register, "/register")
api.add_resource(Detect, "/detect")
api.add_resource(AddTokens, "/addtokens")

if __name__ == "__main__":
    app.run(host='0.0.0.0')
