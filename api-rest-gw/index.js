'use strict'

//Si el usuario se registra correctamente, ponemos una variable a true que nos dejara acceder al contenido


const port = process.env.PORT || 3100;
const URL_WS_VUELO = 'https://localhost:3000/api';
const URL_WS_VEHICULO = 'https://localhost:3001/api';
const URL_WS_HOTEL = 'https://localhost:3002/api';

const express = require('express');
const logger = require('morgan');
const fetch = require('node-fetch');
const mongojs = require('mongojs');
const https = require('https');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jwt-simple');
const moment = require('moment');
const TokenService = require('./tokens');
const OPTIONS_HTTPS = {
    key: fs.readFileSync('./cert/key.pem'),
    cert: fs.readFileSync('./cert/cert.pem') 
};



const app = express();

//var db = mongojs('localhost:27017/SD'); //Conectamos con la DB
var db = mongojs('mongodb+srv://est20:1234@cluster0.dm1rq.mongodb.net/agencia?retryWrites=true&w=majority');
var id = mongojs.ObjectID;
//Declaramos los middleware
app.use(logger('dev'));
app.use(express.urlencoded({extended:false}));
app.use(express.json());

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

function auth(request,response,next){

    if(!request.params.id){
        response.status(401).json({
            result: 'KO',
            mensaje: "NO se especifica la iid del usuario que realiza la llamada"
        })
        return next(new Error("Falta id usuario"));
    }
    var collection = db.collection("agencias");
    collection.findOne({_id: id(request.params.id)}, (err,elemento)=>{
        if(err) response.json(`Id: ${request.params.id}, no valida`);
        console.log(elemento);
        TokenService.decodificaToken(elemento.token)
        .then(userId=>{
            console.log(`Usuario con ID: ${userId} autorizado`);
        })
        .catch(err => response.status(401).json({
            result: 'KO',
            mensaje: "Error autorizacion: Token caducado, debe identificarse nuevamente"
        })
        );
    });

    if(!request.headers.authorization){
        response.status(401).json({
            result: 'KO',
            mensaje: "No se ha enviado el token tipo Bearer en la cabecera Authorization"
        })
        return next(new Error("Falta token de autorizacion"));
    }

    const queToken = request.headers.authorization.split(" ")[1];
    if(queToken === "MITOKEN123456789"){  //JWT
        request.params.token = queToken;  //Creamos nueva propiedad para propagar el token
        return next();
    }

    response.status(401).json({
        result: 'KO',
        mensaje: "Acceso no autorizado a este servicio"
    });
    return next(new Error("Acceso no autorizado"));
}

function isProveedor(request,response,next){
    const queProveedor = request.params.proveedores;

    var queURL = ``;

    switch(queProveedor){
        case "vuelo":
            queURL = `${URL_WS_VUELO}`;
            break;
        case "coche":
            queURL = `${URL_WS_VEHICULO}`;
            break;
        case "hotel":
            queURL = `${URL_WS_HOTEL}`;
            break;
        default:
            response.json(`End-Point invalido: ${queProveedor} no existe`);
    }

    if(request.params.colecciones){
        queURL += `/${request.params.colecciones}`;
    }
    if(request.params.reserva){
        queURL += `/${request.params.reserva}`;
    }
    /*
    if(!request.params.idProveedor){
        if(request.params.idProveedor){
            queURL += `/${request.params.idProveedor}`;
        }
    }
    else{
        if(request.params.id){
            queURL += `/${request.params.id}`;
        }
    }
    */
    if(request.params.idProveedor){
        queURL += `/${request.params.idProveedor}`;
    }

    return queURL;
}
//TOKEN

//GENERACION DE HASH Y SALT
function createHashSalt(request,response,next){
    bcrypt.hash(request.body.password, 10, (err,hash) =>{
        if(err) console.log(err);
        else{
            console.log(`Hash = ${hash}`);
            request.body.password = hash;
            var collection = db.collection("agencias");
            collection.save({user: request.body.user,password: hash, token: null}, (err, elementoGuardado) =>{
            if (err) return next(err);
    
            console.log(elementoGuardado);
            response.status(201).json({
                result: 'OK',
                elemento: elementoGuardado
            });
        });
        }
    });
}

function verifyPassword(hash, request,response,next){
    bcrypt.compare(request.body.password, hash, (err,result)=>{
        console.log(`${hash}`);
        console.log(`Result: ${result}`);

        if(result)
            console.log(`Contraseña correcta`);
        else
            response.json(`Contraseña invalida`);
    });
}

//REGISTRAR USUARIO DE AGENCIA
app.post('/api/registrar', (request, response, next) => {
 
    const user = request.body;
   
    createHashSalt(request, response, next);
  
    
 });
 

 app.get('/api/identificar/:id', (request, response, next) => {
 
    const queID = request.params.id;
    var hash = ``;
    var collection = db.collection("agencias");
    collection.findOne({_id: id(queID)},(err,elemento)=>{
        if(err) response.json(`Id: ${queID}, no válida`);
  
        console.log(elemento);
        hash = elemento.password;
        verifyPassword(hash, request,response,next);
    });
  
  
    //Creamos un token
    const token = TokenService.creaToken(request.params.id);
  
    console.log(token);
    console.log(`Usuario y contraseña correctos`);
    //Decodificar un token
    TokenService.decodificaToken(token)
        .then(userId =>{
            console.log(`Usuario con ID: ${userId} autenticado y autorizado correctamente`);
        })
        .catch(err => response.json(`Token caducado`));
  
    var collection = db.collection("agencias");//guardar por id
    collection.update({_id: id(queID)}, {$set: {token: token}}, function(err, elementoGuardado) {
        if (err || !elementoGuardado) response.json("user not updated");
        else response.json("user updated");
    });
 });
 


//Declaramos nuestras rutas y nuestros controladores
app.get('/api', (request, response, next) =>{
   
    
    //Mi logica de negocio
    response.json( {
        result: "OK",
        proveedores: [
            {
            "proveedor": "coche",
            },
            {
            "proveedor": "vuelo"
            },
            {
            "proveedor": "hotel"
            }
        ]

    });

});

app.get('/api/:proveedores', (request,response,next) =>{
    const queProveedor = request.params.proveedores;
    //const queURL = `${URL_WS}/${queColeccion}`;
    
    var queURL = isProveedor(request,response,next);

    fetch( queURL)
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: json.result,
                colecciones: json.colecciones
                
            });
    });  
});

app.get('/api/:proveedores/:colecciones', (request,response,next) =>{
    const queColeccion = request.params.colecciones;
    var queURL = isProveedor(request,response,next);

    fetch( queURL)
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: json.result,
                colecciones: queColeccion,
                elemento: json.elementos
            });
    });  
});

app.get('/api/:proveedores/:colecciones/:idProveedor', (request,response,next) =>{
    const queColeccion = request.params.colecciones;
    var queURL = isProveedor(request,response,next);

    fetch( queURL)
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: json.result,
                colecciones: queColeccion,
                elemento: json.elementos
            });
    });  
});

//PARA RESERVAS
/*
app.post('/api/:proveedores/:reserva/', auth,(request,response,next) =>{
    const queId = request.params.id;
    const nuevoElemento = request.body;
    var queURL = isProveedor(request,response,next);
    const queToken = request.params.token;
    
    fetch( queURL, {
        method: 'POST',
        body: JSON.stringify(nuevoElemento),
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${queToken}`
        }    
    } )
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: 'OK',
                elemento: json.elemento
            });
    });  

});*/

app.post('/api/:proveedores/:colecciones/:id', auth,(request,response,next) =>{
    const nuevoElemento = request.body;
    const queColeccion = request.params.colecciones;
    var queURL = isProveedor(request,response,next);
    const queToken = request.params.token;
    fetch( queURL, {
        method: 'POST',
        body: JSON.stringify(nuevoElemento),
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${queToken}`
        }    
    } )
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: 'OK',
                colecciones: queColeccion,
                elemento: json.elemento
            });
    });  

});

app.put('/api/:proveedores/:colecciones/:id/:idProveedor', auth, (request,response,next) =>{
    const queId = request.params.id;
    const nuevoElemento = request.body;
    const queToken = request.params.token;
    const queColeccion = request.params.colecciones;
    var queURL = isProveedor(request,response,next);
    fetch(queURL,{
        method: 'PUT',
        body: JSON.stringify(nuevoElemento),
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${queToken}`
        }  
    })
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: 'OK',
                colecciones: queColeccion,
                elemento: json.elemento
            });
    }); 
    /*request.collection.update(
        { _id: id(queId)},
        { $set: nuevosDatos},
        { safe: true,multi: false},
        (err, resultado)=>{
            if (err) return next(err);

            console.log(resultado);
            response.json({
                result:'OK',
                coleccion: queColeccion,
                resultado: resultado

            });
        }
    );*/
});

app.delete('/api/:proveedores/:colecciones/:id/:idProveedor', auth, (request,response,next)=>{
    const queId = request.params.id;
    const queToken = request.params.token;
    const queColeccion = request.params.colecciones;
    var queURL = isProveedor(request,response,next);
    fetch(queURL,{
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${queToken}`
        }  
    })
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: 'OK',
                colecciones: queColeccion,
                elemento: json.elemento
            });
    }); 
});





/*app.listen(port, () => {
    console.log(`WS API GW del WS REST CRUD ejecutandose en http://localhost:${port}/:colecciones/:id`)
});
*/
https.createServer( OPTIONS_HTTPS, app ).listen(port, () => {
    console.log(`SEC WS API GW del REST CRUD con DB ejecutandose en https://localhost:${port}/:colecciones/:id`)
});



