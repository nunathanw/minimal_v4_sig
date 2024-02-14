export function getFormattedDate() {
  const date = new Date();
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0"); // Month starts from 0, so we add 1 and pad with '0' if necessary
  const day = String(date.getUTCDate()).padStart(2, "0"); // Pad day with '0' if necessary
  const hour = String(date.getUTCHours()).padStart(2, "0");
  const minute = String(date.getUTCMinutes()).padStart(2, "0");
  const second = String(date.getUTCSeconds()).padStart(2, "0");

  return { date: `${year}${month}${day}`, time: `${hour}${minute}${second}` };
}

export function getReformattedTimeStamp(timestamp) {
  timestamp = timestamp.toString();
  const year = timestamp.slice(0, 4);
  const month = timestamp.slice(4, 6);
  const day = timestamp.slice(6, 8);
  const hours = timestamp.slice(8, 10);
  const minutes = timestamp.slice(10, 12);

  // Create a Date object
  const date = new Date(`${year}-${month}-${day}T${hours}:${minutes}:00Z`);

  // Define month names in abbreviated form
  const monthNames = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
  ];

  // Format the date as "Abbreviated Month Hour:Minute"
  const formattedDate = `${
    monthNames[date.getMonth()]
  } ${date.getDate()}, ${date.getHours()}:${date
    .getMinutes()
    .toString()
    .padStart(2, "0")}`;

  return formattedDate;
}

export function getTimeStamp() {
  const formattedDate = getFormattedDate();
  return formattedDate.date + formattedDate.time;
}
