import enum
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

# client = MongoClient("mongodb://db:27017")
client = MongoClient("127.0.0.1:27017")

db = client.SimilarityDB
users = db["Users"]


class HttpStatus(enum.Enum):
    OK = 200,
    INVALID_USER = 301,
    INVALID_PW = 302,
    OUT_OF_TOKENS = 303,
    INVALID_JSON = 304,
    INVALID_ADMIN_PW = 304


class ResourcesType(enum.Enum):
    REGISTER = 1


class JsonSyntax:
    static_user_name = "username"
    static_pw = "password"
    static_sentences = "sentences"
    static_tokens = "tokens"

    @staticmethod
    def message(message: str, http_return_code: HttpStatus):
        return {
            "Message": message,
            "Status Code": http_return_code.value
        }


class Register(Resource):
    def __is_valid(self, posted_data: dict):
        if JsonSyntax.static_user_name in posted_data and JsonSyntax.static_pw in posted_data:
            return HttpStatus.OK

        return HttpStatus.INVALID_JSON

    def post(self):
        posted_data = request.get_json()
        if self.__is_valid(posted_data) == HttpStatus.INVALID_JSON:
            return jsonify(JsonSyntax.message("Invalid input", HttpStatus.INVALID_JSON))

        user_name = posted_data[JsonSyntax.static_user_name]
        if users.find_one({JsonSyntax.static_user_name: user_name}) is not None:
            return jsonify(JsonSyntax.message("User Exists", HttpStatus.INVALID_USER))

        password = posted_data[JsonSyntax.static_pw]
        hash_password = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert({
            JsonSyntax.static_user_name: user_name,
            JsonSyntax.static_pw: hash_password,
            JsonSyntax.static_sentences: "",
            JsonSyntax.static_tokens: 6
        })

        return jsonify(JsonSyntax.message(user_name + " was register!", HttpStatus.OK))


api.add_resource(Register, "/register")

if __name__ == "__main__":

    app.run(host='0.0.0.0')
