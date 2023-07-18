from kavenegar import KavenegarAPI, APIException, HTTPException
from setting import KAVENEGAR_API

api = KavenegarAPI(KAVENEGAR_API)


def send_otp_code(otp_code, phone_number):
    try:
        params = {
            'sender': 'SENDER_NAME',
            'receptor': phone_number,
            'message': f'Your OTP code is: {otp_code}'
        }
        # response = api.sms_send(params)
        # print(response)
    except APIException as e:
        print(f'Kavenegar API Exception: {str(e)}')
    except HTTPException as e:
        print(f'Kavenegar HTTP Exception: {str(e)}')
