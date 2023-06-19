import json
from rest_framework.views import APIView
from django.http import JsonResponse
import pickle
import numpy as np
from .phishing_url_detection import DETECTION

loaded_model = pickle.load(open("C:\\Users\\Hp\\Documents\\Final Year Project\\Phishing Website Detection\\ML Work\\XGBoostClassifier.pickle.dat", "rb"))

class URLPredictionApiView(APIView):
    def post(self, request):
        js = str(request.data).replace("'", '"')
        # GET THE URL FROM THE API
        url = json.loads(js)['url']
        detection = DETECTION()
        # CALL THE DETECTION METHOD HERE
        prediction = detection.featureExtractions(url)
        prediction.insert(10, 0)
        data = prediction
        #data1 = np.array(data)
        #data2 = data1.reshape((1, 14))
        #model = loaded_model.predict(data2)
        response_data = {"success": True, "detection": data}
        print(json.dumps(response_data))  # Print the JSON response
        return JsonResponse(response_data, safe=False)






