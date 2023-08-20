import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime
from urllib.parse import quote, urlencode

import requests

logger = logging.getLogger(__name__)
VERSION = "0.0.1"
ALIYUN_SMS_URL = "https://dysmsapi.aliyuncs.com/"
TAOBAO_TIMESTAMP_URL = "https://api.m.taobao.com/rest/api3.do?api=mtop.common.getTimestamp"
# 阿里云接口错误码，翻译为所需错误消息
MESSAGE_TRANSLATE = {
    "isv.BUSINESS_LIMIT_CONTROL": "验证码发送超过限制，请稍后再试"
}
RANDOM_STRING_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


class SMSError(Exception):
    """API错误基类"""
    pass


class RequestError(SMSError):
    """请求错误，未能返回结果"""
    pass


class APIError(SMSError):
    """接口返回结果，但是状态异常

    :param code: 阿里云错误码
    :param message: 原因
    """
    def __init__(self, code, message):
        self.code = code
        self.message = message


def get_random_string(length, allowed_chars=RANDOM_STRING_CHARS):
    """生成随机字符串"""
    return "".join(secrets.choice(allowed_chars) for _ in range(length))


def get_timestamp():
    """获取当前时间戳

    为避免本地时钟不准确，首先尝试从淘宝获取时间戳
    """
    try:
        return int(requests.get(TAOBAO_TIMESTAMP_URL).json()["data"]["t"]) / 1000
    except Exception:
        logger.exception("get ts from taobao failed")
    return time.time()


class AliSMS:
    def __init__(self, access_key_id, access_key_secret, url=ALIYUN_SMS_URL, *,
                 sign_name=None, template_code=None, timestamp=None, timeout=None,
                 message_translate=MESSAGE_TRANSLATE):
        """
        初始化传入一些能够复用的参数
        :param access_key_id: 阿里云 AccessKey ID，此用户必须拥有短信管理权限
        :param access_key_secret: 阿里云 AccessKey Secret，此用户必须拥有短信管理权限
        :param url: 阿里云短信API地址
        :param sign_name: 短信签名名称，此参数在send函数未传入签名时作为默认签名名称使用
        :param template_code: 短信模板编号，此参数在send函数未传入模板时作为默认模板编号使用
        :param timestamp: 允许传入时间戳，校准系统时间
        :param timeout: 短信发送超时时间
        :param message_translate: 将阿里云错误码翻译为自定义错误消息
        """
        self.id = access_key_id
        self.secret = access_key_secret
        self.url = url
        self.sign_name = sign_name
        self.template_code = template_code
        if timestamp is None:
            timestamp = get_timestamp()
        self.timestamp = timestamp
        self.initial_monotonic = time.monotonic()
        self.timeout = timeout
        self.message_translate = message_translate
        self.session = requests.Session()

    def __del__(self):
        self.session.close()

    def get_time_string(self):
        """获取ISO格式UTC时间字符串"""
        now = datetime.utcfromtimestamp(
            self.timestamp + time.monotonic() - self.initial_monotonic
        )
        return now.strftime("%Y-%m-%dT%H:%M:%SZ")

    def sign(self, params):
        """为请求参数生成签名

        :param params: 请求参数
        :return: 签名
        """
        # 阿里云RPC风格接口文档注明了空格被编码为 %20 而非 +
        # 但是 urlencode 函数默认使用 urllib.parse.quote_plus 编码参数，空格将被编码为 +
        # 因而传入 quote_via=quote
        query = urlencode(params, quote_via=quote)
        string_to_sign = "POST&%2F&" + quote(query)
        digest_maker = hmac.new(
            f"{self.secret}&".encode("utf-8"),
            string_to_sign.encode("utf-8"),
            digestmod=hashlib.sha1
        )
        hash_bytes = digest_maker.digest()
        return base64.b64encode(hash_bytes).decode("utf-8")

    def send(self, phone_number, code, sign_name=None, template_code=None):
        """发送短信验证码

        以下实现均基于官方API文档：
        1. 阿里云短信发送文档 https://help.aliyun.com/document_detail/419273.html?spm=a2c4g.419298.0.0.59852b01bH26fl
        2. 阿里云RPC风格接口 https://help.aliyun.com/zh/sdk/product-overview/rpc-mechanism?spm=a2c4g.419298.0.0.7f4130dckTHCGX#sectiondiv-two-7vy-u3i
        """
        sign_name = sign_name or self.sign_name
        assert sign_name, "必须传入短信签名名称"
        template_code = template_code or self.template_code
        assert template_code, "必须传入短信模板编号"

        # Python3.6 之后，字典都为有序字典，手动按照字典序排序参数，可免去排序步骤
        params = {
            "AccessKeyId": self.id,
            "Action": "SendSms",
            "Format": "JSON",
            "PhoneNumbers": phone_number,
            "SignName": sign_name,
            "SignatureMethod": "HMAC-SHA1",
            "SignatureNonce": get_random_string(32),
            "SignatureVersion": "1.0",
            "TemplateCode": template_code,
            "TemplateParam": json.dumps({"code": code}, separators=(",", ":")),
            "Timestamp": self.get_time_string(),
            "Version": "2017-05-25",
        }

        params["Signature"] = self.sign(params)

        try:
            result = self.session.post(self.url, data=params, timeout=self.timeout).json()
        except requests.RequestException as e:
            logger.exception(f"短信请求失败")
            raise RequestError from e

        try:
            code, message = result["Code"], result["Message"]
        except (TypeError, KeyError):
            logger.info("请求结果: %s", result)
            raise APIError("", "接口返回数据格式错误")

        if code != "OK":
            logger.info("短信发送结果：%s", result)
            msg = self.message_translate.get(code, message)
            raise APIError(code, msg)
