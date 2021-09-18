/* global config */

const key = config.API_KEY;

const $form = document.querySelector('#search-form');
const $tablearea = document.querySelector('.table-container-hidden');
let hashValue = '';
const $passwordForm = document.querySelector('#password-form');

$form.addEventListener('submit', function () {
  event.preventDefault();
  const $searchType = $form.elements.search.value;
  const $searchParm = $form.elements.searchparm.value;

  switch ($searchType) {
    case 'email':
      if (isNullOrWhitespace($searchParm)) {
        alert('Please enter a valid email');
      } else {
        if (validateEmail($searchParm)) {
          searchEmail($searchParm);
        } else {
          alert('Email not valid, please enter a valid email');
        }
      }
      break;
    case 'password':
      if (isNullOrWhitespace($searchParm)) {
        alert('Please enter a password value to search');
      } else {
        hashPassword($searchParm);
      }
      break;
    case 'domain':
      if (isNullOrWhitespace($searchParm)) {
        alert('Please enter a valid domain name to search');
      } else {
        if (validateDomain($searchParm)) {
          searchDomain($searchParm);
        } else {
          alert('Domain not valid, please enter a valid Domain');
        }
      }
      break;
    case 'All Sites':
      showAllSites();
      break;
  }
});

function isNullOrWhitespace(input) {
  return !input || input.trim().length < 1;
}

function validateEmail(value) {
  var input = document.createElement('input');

  input.type = 'email';
  input.required = true;
  input.value = value;

  return typeof input.checkValidity === 'function' ? input.checkValidity() : /\S+@\S+\.\S+/.test(value);
}

function validateDomain(value) {
  var input = document.createElement('input');

  input.type = 'text';
  input.required = true;
  input.value = value;
  return typeof input.checkValidity === 'function' ? input.checkValidity() : /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/.test(value);
}

function searchEmail(value) {
  const apiName = 'breachedaccount/';
  httpRequest('email', apiName, value, buildEmailDisplayContent);
  buildDisplayTable();
}

function searchDomain(value) {
  const apiName = 'breaches?domain=';
  httpRequest('domain', apiName, value, buildDomainDisplayContent);
  buildDisplayTable();
}

function showAllSites() {
  const apiName = 'breaches';
  httpRequest('domain', apiName, '', buildAllSiteDisplayContent);
  buildDisplayTable();
}

/**
* Secure Hash Algorithm (SHA1)
* http://www.webtoolkit.info/
**/
function SHA1(msg) {
  function rotateLeft(n, s) {
    var t4 = (n << s) | (n >>> (32 - s));
    return t4;
  }
  /*
  function lsbHex(val) {
    var str = '';
    var i;
    var vh;
    var vl;
    for (i = 0; i <= 6; i += 2) {
      vh = (val >>> (i * 4 + 4)) & 0x0f;
      vl = (val >>> (i * 4)) & 0x0f;
      str += vh.toString(16) + vl.toString(16);
    }
    return str;
  } */

  function cvtHex(val) {
    var str = '';
    var i;
    var v;
    for (i = 7; i >= 0; i--) {
      v = (val >>> (i * 4)) & 0x0f;
      str += v.toString(16);
    }
    return str;
  }
  function Utf8Encode(string) {
    string = string.replace(/\r\n/g, '\n');
    var utftext = '';
    for (var n = 0; n < string.length; n++) {
      var c = string.charCodeAt(n);
      if (c < 128) {
        utftext += String.fromCharCode(c);
      } else if ((c > 127) && (c < 2048)) {
        utftext += String.fromCharCode((c >> 6) | 192);
        utftext += String.fromCharCode((c & 63) | 128);
      } else {
        utftext += String.fromCharCode((c >> 12) | 224);
        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
        utftext += String.fromCharCode((c & 63) | 128);
      }
    }
    return utftext;
  }

  var blockstart;
  var i, j;
  var W = new Array(80);
  var H0 = 0x67452301;
  var H1 = 0xEFCDAB89;
  var H2 = 0x98BADCFE;
  var H3 = 0x10325476;
  var H4 = 0xC3D2E1F0;
  var A, B, C, D, E;
  var temp;
  msg = Utf8Encode(msg);
  var msgLen = msg.length;
  var wordArray = [];
  for (i = 0; i < msgLen - 3; i += 4) {
    j = msg.charCodeAt(i) << 24 | msg.charCodeAt(i + 1) << 16 |
  msg.charCodeAt(i + 2) << 8 | msg.charCodeAt(i + 3);
    wordArray.push(j);
  }
  switch (msgLen % 4) {
    case 0:
      i = 0x080000000;
      break;
    case 1:
      i = msg.charCodeAt(msgLen - 1) << 24 | 0x0800000;
      break;
    case 2:
      i = msg.charCodeAt(msgLen - 2) << 24 | msg.charCodeAt(msgLen - 1) << 16 | 0x08000;
      break;
    case 3:
      i = msg.charCodeAt(msgLen - 3) << 24 | msg.charCodeAt(msgLen - 2) << 16 | msg.charCodeAt(msgLen - 1) << 8 | 0x80;
      break;
  }
  wordArray.push(i);
  while ((wordArray.length % 16) !== 14) wordArray.push(0);
  wordArray.push(msgLen >>> 29);
  wordArray.push((msgLen << 3) & 0x0ffffffff);
  for (blockstart = 0; blockstart < wordArray.length; blockstart += 16) {
    for (i = 0; i < 16; i++) W[i] = wordArray[blockstart + i];
    for (i = 16; i <= 79; i++) W[i] = rotateLeft(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    A = H0;
    B = H1;
    C = H2;
    D = H3;
    E = H4;
    for (i = 0; i <= 19; i++) {
      temp = (rotateLeft(A, 5) + ((B & C) | (~B & D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotateLeft(B, 30);
      B = A;
      A = temp;
    }
    for (i = 20; i <= 39; i++) {
      temp = (rotateLeft(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotateLeft(B, 30);
      B = A;
      A = temp;
    }
    for (i = 40; i <= 59; i++) {
      temp = (rotateLeft(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotateLeft(B, 30);
      B = A;
      A = temp;
    }
    for (i = 60; i <= 79; i++) {
      temp = (rotateLeft(A, 5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotateLeft(B, 30);
      B = A;
      A = temp;
    }
    H0 = (H0 + A) & 0x0ffffffff;
    H1 = (H1 + B) & 0x0ffffffff;
    H2 = (H2 + C) & 0x0ffffffff;
    H3 = (H3 + D) & 0x0ffffffff;
    H4 = (H4 + E) & 0x0ffffffff;
  }
  temp = cvtHex(H0) + cvtHex(H1) + cvtHex(H2) + cvtHex(H3) + cvtHex(H4);

  return temp.toLowerCase();
}

function hashPassword(value) {
  hashValue = SHA1(value);
  const apiName = 'range/';
  httpRequest('password', apiName, hashValue.substring(0, 5), buildPasswordContent);
}

function httpRequest(type, apiName, parm, callback) {
  const xhr = new XMLHttpRequest();
  // xhr.timeout = 2000;
  const proxy = 'https://lfz-cors.herokuapp.com/?url=';
  let baseURL = '';
  let url = '';
  switch (type) {
    case 'email':
      baseURL = 'https://haveibeenpwned.com/api/v3/';
      url = proxy + baseURL + apiName + parm;
      xhr.responseType = 'json';
      break;
    case 'password':
      baseURL = 'https://api.pwnedpasswords.com/';
      url = proxy + baseURL + apiName + parm;
      xhr.responseType = 'text';
      break;
    case 'breach':
      baseURL = 'https://haveibeenpwned.com/api/v3/';
      url = proxy + baseURL + apiName + parm;
      xhr.responseType = 'json';
      break;
    case 'passphrase':
      baseURL = 'https://makemeapassword.ligos.net';
      url = proxy + baseURL + apiName;
      xhr.responseType = 'json';
      break;
    case 'domain':
      baseURL = 'https://haveibeenpwned.com/api/v3/';
      url = proxy + baseURL + apiName + parm;
      xhr.responseType = 'json';
      break;
  }
  xhr.onreadystatechange = function (e) {
    if (xhr.readyState === 4) {
      if (xhr.status === 200) {
        callback(xhr.response);
      } else {
        return [xhr.status, xhr.response];
      }
    }
  };

  // xhr.ontimeout = function () {
  //  alert('Server request time out');
  // };

  xhr.open('GET', url, true);
  xhr.setRequestHeader('hibp-api-key', key);
  xhr.send();

  xhr.onerror = function () {
    alert('cannot process the request, network error , server not reachable');
  };
}

function buildEmailDisplayContent(response) {
  const apiName = 'breach/';
  response.forEach(element => {
    httpRequest('breach', apiName, element.Name, buildColumn);
  });
}

function buildColumn(response) {
  $tablearea.setAttribute('class', 'table-container-visible');
  const $table = document.querySelector('.table');
  const tr = document.createElement('tr');
  const td0 = document.createElement('td');
  const img = document.createElement('img');
  img.setAttribute('class', 'img');
  img.onerror = function () {
    img.src = 'images/not-found.svg';
  };

  td0.appendChild(img);
  tr.appendChild(td0);
  const td1 = document.createElement('td');
  td1.innerHTML = '<p><strong> ' + response.Name + ' : </strong>';

  td1.innerHTML += response.Description + ' </p>';
  tr.appendChild(td1);
  img.src = response.LogoPath;
  $table.appendChild(tr);

}

function buildDisplayTable() {
  $tablearea.innerHTML = '';
  const table = document.createElement('table');
  table.setAttribute('class', 'table');
  $tablearea.appendChild(table);
  const tr = document.createElement('tr');
  table.appendChild(tr);

  const th0 = document.createElement('th');
  const th1 = document.createElement('th');
  th0.textContent = 'Site icon';
  th1.textContent = 'Breach Details';
  tr.appendChild(th0);
  tr.appendChild(th1);

}

function buildPasswordContent(response) {
  let respValues = [];
  let checkValues = [];
  if (response.length > 0) {
    respValues = response.split('\r\n');
    for (let i = 0; i < respValues.length; i++) {
      checkValues = respValues[i].split(':');
      if ((hashValue.substring(0, 5) + checkValues[0].toLowerCase()) === hashValue) {
        buildPassordDisplay(checkValues[1]);
      }
    }
  }
}

function buildPassordDisplay(occurValue) {
  $tablearea.setAttribute('class', 'messageBox');
  $tablearea.innerHTML = '';
  const para = document.createElement('p');
  $tablearea.appendChild(para);
  const span = document.createElement('span');
  span.textContent = `Oh no! This password has occured ${occurValue} in a database of compromised password. If this is your password , you should change it immediately.`;
  para.appendChild(span);
  const div = document.createElement('div');
  $tablearea.appendChild(div);
  div.setAttribute('class', 'password-button');
  const passButton = document.createElement('button');
  div.appendChild(passButton);
  passButton.setAttribute('type', 'button');
  passButton.textContent = 'Generate Complex Password';

}

const $passButton = document.querySelector('.table-container-hidden');
$passButton.addEventListener('click', function () {
  event.preventDefault();
  const $passForm = document.querySelector('.password-selection-hidden');
  $passForm.setAttribute('class', '.password-selection-visible');
});

const $genPassword = document.querySelector('.password-selection-hidden');
$genPassword.addEventListener('submit', function () {
  event.preventDefault();
  const $newPassType = $passwordForm.elements.newPassType.value;

  let apiName = '';
  switch ($newPassType) {
    case 'passphrase':
      apiName = '/api/v1/readablepassphrase/json?pc=10&s=RandomLong';
      httpRequest('passphrase', apiName, '', fillPasswordContent);

      break;
    case 'dictpassphrase':
      apiName = '/api/v1/passphrase/json?pc=10&wc=6';
      httpRequest('passphrase', apiName, '', fillPasswordContent);

      break;
    case 'Prouncepassword':
      apiName = '/api/v1/pronounceable/json?c=10&sc=5';
      httpRequest('passphrase', apiName, '', fillPasswordContent);

      break;
    case 'Hex':
      apiName = '/api/v1/hex/json?c=10&l=16';
      httpRequest('passphrase', apiName, '', fillPasswordContent);

      break;
  }
});

function fillPasswordContent(response) {
  document.getElementById('genPassword').setAttribute('value', response.pws[0]);

}

function buildDomainDisplayContent(response) {
  buildColumn(response[0]);
}

function buildAllSiteDisplayContent(response) {
  response.forEach(element => {
    buildColumn(element);
  });
}
