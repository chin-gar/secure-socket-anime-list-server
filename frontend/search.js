function addToList(anime_id) {
    if (anime_id) {
        const title = document.getElementById(anime_id+"Title")?.innerText;
        console.log(title)
        fetch("/add", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: title ? new URLSearchParams({anime_id: anime_id, title: title}) : new URLSearchParams({anime_id: anime_id})
        }).then(async(response) => {
            console.log(await response.json())
            if (response.ok) {
                let button = document.getElementById("addRm" + anime_id);
                button.setAttribute("onclick", "rmFromList(" + anime_id + ")");
                button.classList.replace("bg-pink-100/75", "bg-red-400/75");
                button.querySelector('svg').querySelector('path').setAttribute("d", "M4.25 12a.75.75 0 0 1 .75-.75h14a.75.75 0 0 1 0 1.5H5a.75.75 0 0 1-.75-.75Z");
                button.querySelector('p').textContent = "Remove from list";
            }
        });
    }
}

function rmFromList(anime_id) {
    if (anime_id) {
        fetch("/remove", {
            method: "DELETE",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({anime_id: anime_id})
        }).then(async(response) => {
            console.log(await response.json())
            if (response.ok) {
                let button = document.getElementById("addRm" + anime_id);
                button.setAttribute("onclick", "addToList(" + anime_id + ")");
                button.classList.replace("bg-red-400/75", "bg-pink-100/75");
                button.querySelector('svg').querySelector('path').setAttribute("d", "M12 3.75a.75.75 0 0 1 .75.75v6.75h6.75a.75.75 0 0 1 0 1.5h-6.75v6.75a.75.75 0 0 1-1.5 0v-6.75H4.5a.75.75 0 0 1 0-1.5h6.75V4.5a.75.75 0 0 1 .75-.75Z");
                button.querySelector('p').textContent = "Add to list";
            }
        });
    }
}
