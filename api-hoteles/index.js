'use strict'

const port = process.env.PORT || 3002;

const https = require('https');
const fs = require('fs');

const OPTIONS_HTTPS = {
    key: fs.readFileSync('./cert/key.pem'),
    cert: fs.readFileSync('./cert/cert.pem') 
};

const express = require('express');
const logger = require('morgan');
const mongojs = require('mongojs');


const app = express();

//var db = mongojs('localhost:27017/SD'); //Conectamos con la DB
var db = mongojs('mongodb+srv://est20:1234@cluster0.dm1rq.mongodb.net/hotel?retryWrites=true&w=majority');
var id = mongojs.ObjectID;

//Declaramos los middleware
app.use(logger('dev'));
app.use(express.urlencoded({extended:false}));
app.use(express.json());

app.param("colecciones", (request,response,next,colecciones)=>{
    console.log('middleware param /api/:colecciones');
    request.collection =db.collection(colecciones);
    return next();
});

function auth(request,response,next){
    if(!request.headers.authorization){
        response.status(401).json({
            result: 'KO',
            mensaje: "No se ha enviado el token tipo Bearer en la cabecera Authorization"
        })
        return next(new Error("Falta token de autorizacion"));
    }

    console.log(request.headers.authorization);
    if(request.headers.authorization.split(" ")[1] === "MITOKEN123456789"){
        return next();
    }

    response.status(401).json({
        result: 'KO',
        mensaje: "Acceso no autorizado a este servicio"
    });
    return next(new Error("Acceso no autorizado"));
}

//Declaramos nuestras rutas y nuestros controladores
app.get('/api', (request, response, next) =>{
    db.getCollectionNames((err, colecciones) => {
        if(err) return next(err); //Propagamos el error

        console.log(colecciones);
        response.json({
            result: 'OK',
            colecciones: colecciones 
        });
    });
});

app.get('/api/:colecciones', (request,response,next) =>{
    const queColeccion = request.params.colecciones;

    request.collection.find((err,elementos)=>{
        if(err) return next(err);

        console.log(elementos);
        response.json({
            result: 'OK',
            colecciones: queColeccion,
            elementos: elementos
        });
    });
});

app.get('/api/:colecciones/:id', (request,response,next) =>{
    const queColeccion = request.params.colecciones;
    const queId = request.params.id;
    request.collection.findOne({_id: id(queId)},(err,elemento)=>{
        if(err) return next(err);

        console.log(elemento);
        response.json({
            result: 'OK',
            colecciones: queColeccion,
            elementos: elemento
        });
    });
});

app.post('/api/:colecciones', auth,(request,response,next) =>{
    const nuevoElemento = request.body;
    const queColeccion = request.params.colecciones;
    
    request.collection.save(nuevoElemento, (err, elementoGuardado) =>{
        if (err) return next(err);

        console.log(elementoGuardado);
        response.status(201).json({
            result: 'OK',
            coleccion: queColeccion,
            elemento: elementoGuardado
        });
    });
});

app.put('/api/:colecciones/:id', auth, (request,response,next) =>{
    const queColeccion = request.params.colecciones;
    const nuevosDatos = request.body;
    const queId = request.params.id;
    request.collection.update(
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
    );
});

app.delete('/api/:colecciones/:id', auth, (request,response,next)=>{
    const queColeccion = request.params.colecciones;
    const queId = request.params.id;
    request.collection.remove(
        {_id: id(queId)},
        (err,resultado)=>{
            if (err) return next(err);
            response.json(resultado);
        }
    );
});

https.createServer( OPTIONS_HTTPS, app ).listen(port, () => {
    console.log(`SEC WS API REST CRUD con DB ejecutandose en https://localhost:${port}/:colecciones/:id`)
});

/*
app.listen(port, () => {
    console.log(`WS API REST CRUD con DB ejecutandose en http://localhost:${port}/:colecciones/:id`)
});
*/


