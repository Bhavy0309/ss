
let input = document.getElementById('inputBox');
let buttons =  document.querySelectorAll('button');

let string = '';
let arr = Array.from(buttons);
arr.forEach(button => {
    button.addEventListener('click', (e) =>{
        if(e.target.innerHTML == '='){
            string = eval(string);
            input.value = string;
            console.log(string + " key was pressed!");
    
        }
        else if(e.target.innerHTML == 'AC'){
            string = ""
            input.value = string;
        }
        else if(e.target.innerHTML == 'DEL'){
            string = string.substring(0, string.length-1);
            input.value = string;
        }
        
        else{
        string += e.target.innerHTML;
        input.value = string;
        
        }

        document.addEventListener("keydown", function(event) {
    if (event.key === "Enter") {
        console.log("Enter key was pressed!");
        event.preventDefault(); // Prevent default action if needed
    }
});
})})
