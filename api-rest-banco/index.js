'use strict'

const port = process.env.PORT || 3003;

const https = require('https');
const fs = require('fs');

const OPTIONS_HTTPS = {
    key: fs.readFileSync('./cert/key.pem'),
    cert: fs.readFileSync('./cert/cert.pem') 
};

const express = require('express');
const logger = require('morgan');
const mongojs = require('mongojs');
const bcrypt = require('bcrypt');

const app = express();

//var db = mongojs('localhost:27017/SD'); //Conectamos con la DB
var db = mongojs('mongodb+srv://est20:1234@cluster0.dm1rq.mongodb.net/banco?retryWrites=true&w=majority');
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
   
    if(request.body.pin != null){
        
        createHashSalt(request, response, next);
    }
    else{
        response.json(`Error: Formato del body inválido`);
    }
 });
 
 //GENERACION DE HASH Y SALT
function createHashSalt(request,response,next){
    var saldo = request.body.saldo;
    if(request.body.saldo==null)
        saldo = 0;
    bcrypt.hash(request.body.pin, 10, (err,hash) =>{
        if(err) console.log(err);
        else{
            console.log(`Hash = ${hash}`);
            request.body.pin = hash;
            var collection = db.collection("cuentas");
            collection.save({pin: hash, saldo: saldo}, (err, elementoGuardado) =>{
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

function verifyPassword(elemento, request,response,next){
    var newSaldo;
    bcrypt.compare(request.body.pin, elemento.pin, (err,result)=>{
        console.log(`${elemento.pin}`);
        console.log(`Result: ${result}`);

        if(result){
            console.log(`Pin correcto`);
            newSaldo = elemento.saldo;
            if(newSaldo - request.body.precio < 0){
                response.json(`Error: saldo insuficiente`)
            }
            else{
                newSaldo -= request.body.precio;
                request.collection.update(
                    { _id: id(request.params.id)},
                    { $set: {saldo: newSAldo}},
                    { safe: true,multi: false},
                    (err, resultado)=>{
                        if (err) return next(err);
            
                        console.log(resultado);
                        response.json({
                            //result:'OK',
                            //coleccion: queColeccion,
                            resultado: resultado
            
                        });
                    }
                );
            }
           
        }
        else
            response.json(`Pin incorrecto`);
            return false;
    });
}

app.put('/api/:colecciones/:id', auth, (request,response,next) =>{
    const queColeccion = request.params.colecciones;
    const queId = request.params.id;

    request.collection.findOne({_id: id(queId)},(err,elemento)=>{
        if(err) return next(err);
        else{
            verifyPassword(elemento,request,response,next)
            
        }
    });  
    
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

//RESERVAS
app.post('/api/reserva/:id', auth,(request,response,next) =>{
    const queID = request.params.id;
    var collection = db.collection("reserva");
    
    collection.save({'_id':queID}, (err, elementoGuardado) =>{
        if (err) return next(err);

        console.log(elementoGuardado);
        response.status(201).json({
            result: 'OK',
            elemento: elementoGuardado
        });
    });
});


//
https.createServer( OPTIONS_HTTPS, app ).listen(port, () => {
    console.log(`SEC WS API REST CRUD con DB ejecutandose en https://localhost:${port}/:colecciones/:id`)
});

