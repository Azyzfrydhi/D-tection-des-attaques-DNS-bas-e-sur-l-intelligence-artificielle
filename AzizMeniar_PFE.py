#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from elasticsearch import Elasticsearch
import pandas as pd
import whois
from datetime import datetime
from scipy.stats import entropy
import tldextract
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.impute import SimpleImputer
import pickle
from pathlib import Path 
import numpy as np
from elasticsearch.helpers import bulk
import json
from elasticsearch.helpers import scan
import os
from elasticsearch.exceptions import NotFoundError
import pymongo



import time
from elasticsearch import exceptions


import warnings
from elasticsearch import ElasticsearchWarning

# Ignore ElasticsearchWarning messages
warnings.filterwarnings("ignore", category=ElasticsearchWarning)


# from tenacity import retry, stop_after_attempt, wait_fixed

# @retry(stop=stop_after_attempt(5), wait=wait_fixed(30))
# def connect_to_elasticsearch():
#     es = None
#     try:
#         es = Elasticsearch([{"host": "172.29.12.112", "port": 9200}], timeout=20)
#         if es.ping():
#             print("Connected to Elasticsearch")
#             return es
#     except exceptions.ConnectionError as e:
#         print("ConnectionError:", str(e))
#         raise Exception("Failed to connect to Elasticsearch after multiple attempts")

# es = connect_to_elasticsearch()













# /////////////////////////////////Connecter aux les bases de donneés à l'aide de connecteurs Python//////////////////////////////////////////////////////////////////////////


es= Elasticsearch ([{"host":"172.29.12.112","port":9200}],timeout=30)
print(es.ping())

mongo_uri = "mongodb://172.29.12.112:27017/"
client = pymongo.MongoClient(mongo_uri)


# ///////////////////////////////////////////////////////////analyse des donneés////////////////////////////////////////////////////////////////////////

while True:
    # MongoDB configuration

    mongo_db = client["mydatabase"]
    mongo_collection = mongo_db["DNS_logs"]




    scroll_id_file = "point.txt"

    # Check if the scroll ID file exists
    if os.path.exists(scroll_id_file):
        # Read the scroll ID from the file
        with open(scroll_id_file, "r") as f:
            scroll_id = f.read().strip()

        try:
            # Fetch the next 500 hits using the scroll ID
            res = es.scroll(scroll_id=scroll_id, scroll='1m')
        except NotFoundError:
            # Reinitialize the scroll if the scroll ID is not valid anymore
            query = {
                "size": 500,
                "query": {
                    "match_all": {}
                },
                "sort": [
                    {"@timestamp": {"order": "desc"}}
                ]
            }
            res = es.search(index='packetbeat-*', body=query, scroll='1m')
            scroll_id = res['_scroll_id']

    else:
        # Initialize the scroll
        query = {
            "size": 500,
            "query": {
                "match_all": {}
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ]
        }

        # Execute the query and get the results
        res = es.search(index='packetbeat-*', body=query, scroll='1m')

        # Save the scroll ID
        scroll_id = res['_scroll_id']

    # Save the scroll ID to the file
    with open(scroll_id_file, "w") as f:
        f.write(scroll_id)

    # Obtaining the source data from Elasticsearch hits and saves it in a list called logs
    logs = [hit['_source'] for hit in res['hits']['hits']]

    
    
    # Convert the list of hits to a pandas dataframe
    d = pd.DataFrame(logs)


#     dns_normalized = pd.json_normalize(d['dns'])
#     d= pd.concat([d.drop('dns', axis=1), dns_normalized], axis=1)
#     d.head()
    if 'dns' in d.columns:

        d= pd.concat([d.drop('dns', axis=1), pd.json_normalize(d['dns'])], axis=1)


        # # Drop any rows with missing values
        d.dropna(how='any', inplace=True)


        records = d.to_dict("records")

        # Insert the records into MongoDB
        mongo_collection.insert_many(records)






            # Get unique domain names from the DNS traffic data
        domains = d['question.name'].unique().tolist()

        dd = []
        enriched_data = []
        for domain in domains:
            try:
                w = whois.whois(str(domain))
                creation_date = w.creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(w.creation_date, datetime) else None
                expiration_date = w.expiration_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(w.expiration_date, datetime) else None
                age_days = None
                lifespan_days = None
                if creation_date and expiration_date:
                    age_days = (datetime.now() - datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')).days
                    lifespan_days = (datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S') - datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')).days
                entropy_score = entropy(list(str(domain).encode('utf-8')))
                if isinstance(domain, str):
                    num_percent = sum(c.isdigit() for c in domain) / len(domain)
                else:
                    num_percent = None  

                # Get the SLD 
                if isinstance(domain, str):
                    subdomain = tldextract.extract(domain).subdomain
                else:
                    subdomain = None

                # Get the ASN 
                ip_whois = whois.whois(str(domain))
                asn = ip_whois.get('asn')

                data = {
                    'domain': domain,
                    'SLDd': subdomain,
                    'creation_date': creation_date,
                    'expiration_date': expiration_date,
                    'registrar': w.registrar,
                    'email': w.emails,
                    'org': w.org,
                    'Country': w.country,
                    'domain_age': age_days,
                    'domain_lifespan': lifespan_days,
                    'length': len(str(domain)),  
                    'state': w.state,
                    'entropy': entropy_score,
                    'num%': num_percent,
                    'ASN': asn
                }
                              
                enriched_data.append(data)
#                 dd = [{'email': data['email'], 'domainplus': d['question.name']} for data in enriched_data]

            except whois.parser.PywhoisError:
                pass

            # Create a new DataFrame with the enriched data
        enriched_df = pd.DataFrame(enriched_data)

            # Merge the enriched DataFrame with the original DNS traffic data based on the domain name
        d1 = pd.merge(d, enriched_df, how='left', left_on='question.name', right_on='domain')
        d1.drop(['domain'], axis=1, inplace=True)




        d2= d1.rename(columns={'question.top_level_domain': 'TLD', 'answer.ttl': 'TTL','resolved_ip':'IP', 'question.name':'Domain','question.subdomain':'SLD'})



        columns_to_drop = ['@timestamp', 'destination', 'source', 'type', 'response_code', 'email','question.type','question.class'
                                  , 'question.etld_plus_one', 'answer.class','question.registered_domain','SLDd']
        d2= d2.drop(columns=columns_to_drop)

        d2['Domain'] = d2['Domain'].apply(lambda x: '.'.join(x.split('.')[-2:]))

        new_order = ['Country', 'TTL', 'IP', 'Domain', 'TLD', 'SLD', 'entropy',
               'num%', 'length', 'state', 'creation_date', 'expiration_date',
               'domain_age', 'domain_lifespan', 'registrar', 'org']
        d2 = d2[new_order]


        d2['Domain']= d2['Domain'].drop_duplicates()


            # # Drop any rows with missing values
        d2.dropna(how='any',inplace=True)
        d2 = d2[~d2['Domain'].isin(['fastly.NET', 'ntp.org', 'nessus.org','facebook.com','edgdns-tm.inf','cloudflare.com'])]



            # Create a copy of d2
        d2_encoded = d2.copy()
        if len(d2) !=0:
    #=====================================================================================================
                # Get the list of categorical and numerical columns
            categorical_cols = d2.select_dtypes(include=['object']).columns.tolist()
            numerical_cols = d2.select_dtypes(include=['float', 'int']).columns.tolist()

                # Encode the categorical columns using LabelEncoder
            le = LabelEncoder()
            for col in categorical_cols:
                d2_encoded[col] = le.fit_transform(d2_encoded[col].astype(str))

                # Fill the missing values in the numerical columns
            imputer = SimpleImputer(strategy='mean')
            d2_encoded[numerical_cols] = imputer.fit_transform(d2_encoded[numerical_cols])

                # Normalize the numerical columns
            scaler = StandardScaler()
            d2_encoded[numerical_cols] = scaler.fit_transform(d2_encoded[numerical_cols])

            pickle_file = Path("C:/Users/MSI/OneDrive/Bureau/rapport/dt_classifier_model.pkl")

            with pickle_file.open(mode='rb') as f:
                foo = pickle.load(f)

            prediction = foo.predict(d2_encoded)
            print(prediction)
            df_pred = d2_encoded.copy()

            d2['prediction'] = prediction
            d2['prediction'] = d2['prediction'].replace({0: 'benigne', 1: 'malicious'})
#             email_value = dd[0]['email']
#             domainplus_value = dd[0]['domainplus']
#             d2['email'] = email_value
#             d2['domainplus'] = domainplus_value
#             d2.columns




            # Convert the DataFrame to a list of dictionaries
            documents = d2.to_dict(orient='records')

            # Define the mapping for the index
            mapping = {
                "mappings": {
                    "properties": {
                        "client_ip": {"type": "ip"},
                        "query": {"type": "text"}
                    }
                }
            }

        # , "ignore_malformed": True

            # Check if the index already exists
            if es.indices.exists(index='prediction'):
                print("Index 'prediction' already exists ")
            else:
                # Create the index with the specified mapping
                es.indices.create(index='prediction', body=mapping)
                print("Index 'pridection' created.")

            # Insert the documents into the index
            actions = [
                {"_index": "prediction", "_source": doc} for doc in documents
            ]
            bulk(es, actions)
            print("Documents inserted into index prediction ")

            # Update the documents in the index
            for doc in documents:
                # Check if the document has a 'client_ip' field
                if 'client_ip' not in doc:
                    continue

                # Use the "client_ip" field as the document ID
                doc_id = doc['client_ip']
                try:
                    # Try to update the document with the same ID
                    es.update(index='prediction', id=doc_id, body={"doc": doc})
                    print(f"Document with ID {doc_id} updated.")
                except Exception as e:
                    print(f"Could not update document with ID {doc_id}. Error: {e}")





# In[35]:


d.columns

# # #obtaining the source data from Elasticsearch hits and saves it in a list called logs
# logs = [hit['_source'] for hit in res['hits']['hits']]
# d = pd.DataFrame(logs)


# In[33]:


d1['question.name'].unique()


# In[4]:


# import tldextract

# # Get unique domain names from the DNS traffic data
# domains = d['question.name'].unique().tolist()

# # Enrich the DNS traffic data with WHOIS information
# enriched_data = []
# for domain in domains:
#     try:
#         w = whois.whois(str(domain))
#         creation_date = w.creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(w.creation_date, datetime) else None
#         expiration_date = w.expiration_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(w.expiration_date, datetime) else None
#         age_days = None
#         lifespan_days = None
#         if creation_date and expiration_date:
#             age_days = (datetime.now() - datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')).days
#             lifespan_days = (datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S') - datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')).days
#         entropy_score = entropy(list(str(domain).encode('utf-8')))
#         if isinstance(domain, str):
#             num_percent = sum(c.isdigit() for c in domain) / len(domain)
#         else:
#             num_percent = None  
        
#         # Get the SLD 
#         if isinstance(domain, str):
#             subdomain = tldextract.extract(domain).subdomain
#         else:
#             subdomain = None
        
#         # Get the ASN 
#         ip_whois = whois.whois(str(domain))
#         asn = ip_whois.get('asn')
        
#         data = {
#             'domain': domain,
#             'SLD': subdomain,
#             'creation_date': creation_date,
#             'expiration_date': expiration_date,
#             'registrar': w.registrar,
#             'email': w.emails,
#             'org': w.org,
#             'Country': w.country,
#             'domain_age': age_days,
#             'domain_lifespan': lifespan_days,
#             'length': len(str(domain)),  
#             'state': w.state,
#             'entropy': entropy_score,
#             'num%': num_percent,
#             'ASN': asn
#         }
#         enriched_data.append(data)
#     except whois.parser.PywhoisError:
#         pass
        
# # Create a new DataFrame with the enriched data
# enriched_df = pd.DataFrame(enriched_data)

# # Merge the enriched DataFrame with the original DNS traffic data based on the domain name
# d1 = pd.merge(d, enriched_df, how='left', left_on='question.name', right_on='domain')
# d1.drop(['domain'], axis=1, inplace=True)


# In[5]:


# d1.head(10)
# d2= d1.rename(columns={'question.top_level_domain': 'TLD', 'answer.ttl': 'TTL','resolved_ip':'IP', 'question.name':'Domain'})


# In[6]:


# columns_to_drop = ['@timestamp', 'destination', 'source', 'type', 'response_code', 'email',
#                    'question.type', 'question.class', 'question.etld_plus_one', 'answer.class','question.subdomain','question.registered_domain']
# d2= d2.drop(columns=columns_to_drop)


# In[7]:


# new_order = ['Country' ,'IP', 'Domain', 'TLD', 'SLD' ,'state', 'creation_date',
#  'expiration_date', 'registrar', 'org' ,'ASN', 'TTL' ,'entropy','num%', 'length',
#  'domain_age', 'domain_lifespan']
# d2 = d2[new_order]


# In[8]:


# # Drop any rows with missing values
# enriched_df.dropna(inplace=True)
# print(d2.columns)
# d2.head()


# In[9]:


print(d2.isnull().sum())
d2


# In[10]:


# from sklearn.preprocessing import LabelEncoder, StandardScaler
# from sklearn.impute import SimpleImputer

# # Create a copy of d2
# d2_encoded = d2.copy()

# # Get the list of categorical and numerical columns
# categorical_cols = d2.select_dtypes(include=['object']).columns.tolist()
# numerical_cols = d2.select_dtypes(include=['float', 'int']).columns.tolist()

# # Encode the categorical columns using LabelEncoder
# le = LabelEncoder()
# for col in categorical_cols:
#     d2_encoded[col] = le.fit_transform(d2_encoded[col].astype(str))

# # Fill the missing values in the numerical columns
# imputer = SimpleImputer(strategy='mean')
# d2_encoded[numerical_cols] = imputer.fit_transform(d2_encoded[numerical_cols])

# # Normalize the numerical columns
# scaler = StandardScaler()
# d2_encoded[numerical_cols] = scaler.fit_transform(d2_encoded[numerical_cols])












# In[11]:


d2_encoded.columns 


# In[12]:


# import pickle
# from pathlib import Path 
# import numpy as np


# pickle_file = Path("C:/Users/MSI/Downloads/test/knn_model.pkl")

# with pickle_file.open(mode='rb') as f:
#     foo = pickle.load(f)

# prediction = foo.predict(d2_encoded)
# print(prediction)
# df_pred = d2_encoded.copy()

# d2['prediction'] = prediction
# d2['prediction'] = d2['prediction'].replace({0: 'benigne', 1: 'malicious'})
# d2.columns 


# In[13]:


from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import json



# index="prediction"
# if es.indices.exists(index=index):
#     es.indices.delete(index=prediction,ignore=[400,404])

    
    
#  index mapping
mapping = {
    "mappings": {
        "properties": {
            "Country": {"type": "keyword"},
            "IP": {"type": "ip"},
            "Domain": {"type": "keyword"},
            "TLD": {"type": "keyword"},
            "SLD": {"type": "keyword"},
            "state": {"type": "keyword"},
            "creation_date": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
            "expiration_date": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
            "registrar": {"type": "keyword"},
            "org": {"type": "keyword"},
            "TTL": {"type": "integer"},
            "entropy": {"type": "float"},
            "num%": {"type": "float"},
            "length": {"type": "integer"},
            "domain_age": {"type": "integer"},
            "domain_lifespan": {"type": "integer"},
            "prediction": {"type": "keyword"}
        }
    }
}

# Create the Elasticsearch index with the specified mapping
es.indices.create(index="prediction1", body=mapping)

# insert it into the Elasticsearch index
d2_json = json.loads(d2.to_json(orient="records"))
actions = [{"_index": "prediction1", "_source": doc} for doc in d2_json]
bulk(es, actions)


# In[ ]:




