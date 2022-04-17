# -*- coding: utf-8 -*-

from flask import Flask, session, redirect, url_for, escape, request, render_template


import os
import boto3


application = Flask(__name__)
application.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


ACCESS_KEY_ID = ''
ACCESS_SECRET_KEY = ''
AWS_REGION = ''


#Creating Session With Boto3.
_session = boto3.Session(  aws_access_key_id=ACCESS_KEY_ID,
                          aws_secret_access_key=ACCESS_SECRET_KEY,
                          region_name=AWS_REGION
)


dynamodb = boto3.resource('dynamodb',
                          aws_access_key_id=ACCESS_KEY_ID,
                          aws_secret_access_key=ACCESS_SECRET_KEY,
                          region_name=AWS_REGION)

from boto3.dynamodb.conditions import Key, Attr



@application.route('/')
def home():
    if(session.get('email') != None):
        #get values in dynamoDb
        table = dynamodb.Table('events')
        response = table.scan()
        items = response['Items']

        return render_template('home.html', events = items)
    else:
        return render_template('login.html')


@application.route('/login')
def login():
    if (session.get('email') != None):
        return render_template('home.html')
    else:
        return render_template('login.html')


@application.route('/logout')
def logout():
    session.pop('email', None)
    return login()

@application.route('/myevents')
def myEvents():
    if (session.get('email') != None):

        #get values for user in dynamoDb
        table = dynamodb.Table('events')

        response = table.scan(FilterExpression=Attr('userEmail').contains(session.get('email')))

        items = response['Items']

        return render_template('my-events.html', events = items)

    else:
        return render_template('login.html')



#kullanıcı kayıt işlemi.
@application.route('/signup', methods=['post','get'])
def signup():

    if request.method == 'GET':
        return render_template('index.html')

    if request.method == 'POST':
        name = request.form['name']
        surname = request.form['surname']
        email = request.form['email']
        password = request.form['password']

        # users adli tabloya baglanir
        table = dynamodb.Table('users')

        # Girilen email ile veritabanindaki emaili kiyaslar
        checkUser = table.query(
            KeyConditionExpression=Key('email').eq(email)
        )
        userExists = True
        try:
            items = checkUser['Items']
            username = items[0]['email']
        except:
            userExists = False

        if userExists:
            return render_template('index.html', msg='Bir seyler basarisiz gitti...')

        table.put_item(
            Item={
                'name': name,
                'surname': surname,
                'email': email,
                'password': password
            }
        )
        msg = "Registration Complete. Please Login to your account !"

        return render_template('login.html', msg=msg)
    return render_template('index.html')

#login işlemi
@application.route('/check', methods=['post'])
def check():
    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        try:
            table = dynamodb.Table('users')
            response = table.query(
                KeyConditionExpression=Key('email').eq(email)
            )
            items = response['Items']
            name = items[0]['name']
            if password == items[0]['password']:
                #create session
                session.setdefault('email',email)
                return home()
            else:
                return login()
        except:
            pass


    return login()

#add event
@application.route('/addEvent', methods=['post'])
def addEvent():
    if request.method == 'POST':

        eventName = request.form['eventName']
        eventDescription = request.form['eventDescription']
        eventCategory = request.form['eventCategory']
        eventImage = request.form['eventImage']

        #kullanıcı idsi ile dynamo dbye veriler kayıt olunacak

        # Creating S3 Resource From the Session.
        s3 = _session.resource('s3')
        result = s3.Bucket('mybucketformycloudproject').upload_file(os.path.abspath("Images\\"+eventImage),session.get('email')+'/'+eventImage)

        #create dynnamoDb

        table = dynamodb.Table('events')
        table.put_item(
            Item={
                'eventId': eventName+eventCategory,
                'eventName': eventName,
                'eventDescription': eventDescription,
                'eventCategory': eventCategory,
                'eventImage': "https://mybucketformycloudproject.s3.amazonaws.com/"+session.get('email')+'/'+eventImage,
                'userEmail': session.get('email')
            }
        )


    return home()


#delete event
@application.route('/delete/<string:eventId>', methods=['GET'])
def deleteEvent(eventId):
    if request.method == 'GET':

        table = dynamodb.Table('events')
        response = table.scan(FilterExpression=Attr('eventId').contains(eventId))
        items = response['Items']

        temp = items[0]['eventImage']
        print(temp[51:])
        client = boto3.client('s3',
                                 aws_access_key_id=ACCESS_KEY_ID,
                                 aws_secret_access_key=ACCESS_SECRET_KEY)
        client.delete_object(Bucket='mybucketformycloudproject', Key=temp[51:])

        table.delete_item(
            Key={
                'eventId': eventId
            }
        )

    return myEvents()



if __name__ == "__main__":
    application.run(debug=True, host='localhost')
