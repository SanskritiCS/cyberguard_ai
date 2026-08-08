import asyncio
from gemini_service import generate_reply

async def main():
    try:
        reply = await generate_reply("what is phishing attack?")
        print("REPLY:", reply)
    except Exception as e:
        print("ERROR:", e)

if __name__ == "__main__":
    asyncio.run(main())
