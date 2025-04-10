const phrases = [
    "FUTURE OF VOTING IS HERE",
    "YOUR VOTE. YOUR VOICE.",
    "DIGITAL. SECURE. RELIABLE.",
    "BLOCKCHAIN-POWERED DEMOCRACY"
];

let i = 0;
let j = 0;
let currentPhrase = [];
let isDeleting = false;
let isEnd = false;

function loop() {
    const dynamicText = document.getElementById('dynamic-text');
    isEnd = false;
    dynamicText.innerHTML = currentPhrase.join('');

    if (i < phrases.length) {
        if (!isDeleting && j <= phrases[i].length) {
            currentPhrase.push(phrases[i][j]);
            j++;
            dynamicText.innerHTML = currentPhrase.join('');
        }
        if (isDeleting && j <= phrases[i].length) {
            currentPhrase.pop();
            j--;
            dynamicText.innerHTML = currentPhrase.join('');
        }
        if (j === phrases[i].length) {
            isEnd = true;
            isDeleting = true;
        }
        if (isDeleting && j === 0) {
            currentPhrase = [];
            isDeleting = false;
            i++;
            if (i === phrases.length) {
                i = 0;
            }
        }
    }
    const speed = isEnd ? 2000 : isDeleting ? 50 : 100;
    setTimeout(loop, speed);
}

loop();
