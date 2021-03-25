console.log("Hello World")

const spinnerBox = document.getElementById('spinner-box')
const dataBox = document.getElementById('data-box')

// console.log(spinnerBox)
// console.log(dataBox)

$.ajax({
    type: 'GET',
    url: '/scan/subdomain/',
    success: function(response){
        console.log(response)
    },
    error: function(error){
        console.log(error)
    }
})
