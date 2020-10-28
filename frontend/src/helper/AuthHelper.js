import axios from 'axios';

const key = "authToken";

export function expireAuthToken(){
    localStorage.removeItem(key);
    sessionStorage.removeItem(key);
}

export function getLoggedInUser(){
    let authToken = localStorage.getItem(key) ?? sessionStorage.getItem(key);
    return axios.get('http://localhost:9000/users/user', {
        headers: {
            "x-auth-token": authToken
        }
    }).catch(err => {
        localStorage.removeItem(key);
        sessionStorage.removeItem(key);
    })
    .then(response => {
        if(response){
            let result = response.data;
            return result;
        }
    })
}

export function isLoggedIn(){
    let authToken = localStorage.getItem(key) ?? sessionStorage.getItem(key);
    if(!authToken){
        return false
    }
    return axios.get('http://localhost:9000/users/isLoggedIn', {
        headers: {
            "x-auth-token": authToken
        }
    }).catch(err => {
        localStorage.removeItem(key);
        sessionStorage.removeItem(key);
        return false;
    }).then(response =>{return true});

}

export function setAuthToken(){

}