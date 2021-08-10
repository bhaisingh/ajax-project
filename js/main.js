/* global config */

const key = config.API_KEY;

const $form = document.querySelector('#search-form');
const $tablearea = document.querySelector('.table-container-hidden');

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
      break;
    case 'domain':
      break;
    case 'All Sites':
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

function searchEmail(value) {
  const apiName = 'breachedaccount/';
  httpRequest('email', apiName, value, buildEmailDisplayContent);
  buildDisplayTable();
}

function httpRequest(type, apiName, parm, callback) {
  const xhr = new XMLHttpRequest();
  // xhr.timeout = 2000;
  const proxy = 'https://lfz-cors.herokuapp.com/?url=';
  const baseURL = 'https://haveibeenpwned.com/api/v3/';
  let url = '';
  switch (type) {
    case 'email':
      url = proxy + baseURL + apiName + parm;
      break;
    case 'password':
      break;
    case 'breach':
      url = proxy + baseURL + apiName + parm;
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
  xhr.responseType = 'json';
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
