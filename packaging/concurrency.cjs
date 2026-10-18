function createSlots(limit){
    if(!Number.isSafeInteger(limit)||limit<1) throw new RangeError("Slot limit must be a positive safe integer")
    let active=0
    return {
        tryAcquire(){
            if(active>=limit) return null
            active++
            let released=false
            return ()=>{
                if(released) return
                released=true
                active--
            }
        }
    }
}

module.exports={ createSlots }
